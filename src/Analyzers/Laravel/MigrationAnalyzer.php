<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Laravel;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * Database migration hygiene (Laravel).
 *
 * Flags:
 *  - migrations that declare an `up()` but no `down()` (not reversible)
 *  - data-destructive schema operations in `up()` (dropTable, dropColumn, delete
 *    of a whole table without a re-creation path). A drop is not flagged when
 *    every dropped table/column name re-appears as a string literal in `down()`
 *    (best-effort restore detection).
 *
 * Deliberately not flagged: index/constraint drops (dropIndex, dropUnique,
 * dropForeign, dropPrimary, dropTimestamps) — they carry no row data and are
 * recoverable from the schema, unlike table/column drops.
 *
 * Assumes: only files under a `/database/migrations/` path segment are considered.
 * Reversibility is a best-effort heuristic, so confidence is medium.
 */
final class MigrationAnalyzer extends AbstractAnalyzer
{
    private const RULE_MISSING_DOWN = 'MIGRATION_MISSING_DOWN';
    private const RULE_DESTRUCTIVE_UP = 'MIGRATION_DESTRUCTIVE_UP';

    private const DESTRUCTIVE_METHODS = [
        'dropTable', 'dropIfExists', 'dropColumn', 'delete',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if (!$this->isMigrationFile($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function isMigrationFile(string $file): bool
    {
        return str_contains(str_replace('\\', '/', $file), '/database/migrations/');
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $methods = $this->finder()->findInstanceOf($ast, Node\Stmt\ClassMethod::class);

        $up = null;
        $down = null;

        foreach ($methods as $method) {
            if (!$method instanceof Node\Stmt\ClassMethod) {
                continue;
            }
            $name = $method->name->toString();
            if ($name === 'up') {
                $up = $method;
            } elseif ($name === 'down') {
                $down = $method;
            }
        }

        if ($up !== null && $down === null) {
            $issues[] = $this->makeIssue(
                self::RULE_MISSING_DOWN,
                'Migration defines up() but no down() — it cannot be rolled back safely.',
                $file,
                $up->getStartLine(),
                Severity::Warning,
                ['kind' => 'missing_down'],
                Confidence::Medium
            );
        }

        if ($up !== null && $up->stmts !== null) {
            $destructive = $this->destructiveCalls($up->stmts);
            if ($destructive !== []) {
                $dropped = $this->droppedIdentifiers($destructive);
                if ($dropped === [] || !$this->isRestoredInDown($down, $dropped)) {
                    $issues[] = $this->makeIssue(
                        self::RULE_DESTRUCTIVE_UP,
                        'Destructive schema operation in up(): dropping a table/column that is not re-created in the same migration.',
                        $file,
                        $up->getStartLine(),
                        Severity::Warning,
                        ['kind' => 'destructive_up'],
                        Confidence::Medium
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * @param array<Node\Stmt> $stmts
     * @return list<Node\Expr\MethodCall>
     */
    private function destructiveCalls(array $stmts): array
    {
        $found = $this->finder()->find($stmts, function (Node $node): bool {
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array($node->name->toString(), self::DESTRUCTIVE_METHODS, true);
            }

            return false;
        });

        return array_values(array_filter(
            $found,
            static fn (Node $node): bool => $node instanceof Node\Expr\MethodCall
        ));
    }

    /**
     * @param list<Node\Expr\MethodCall> $calls
     * @return list<string>
     */
    private function droppedIdentifiers(array $calls): array
    {
        $names = [];
        foreach ($calls as $call) {
            if (!$call->name instanceof Node\Identifier) {
                continue;
            }
            $method = $call->name->toString();
            if ($method === 'delete') {
                continue;
            }
            foreach ($call->args as $arg) {
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                $names = array_merge($names, $this->stringValues($arg->value, $method === 'dropColumn'));
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * @return list<string>
     */
    private function stringValues(Node\Expr $expr, bool $recurseArray): array
    {
        if ($expr instanceof Node\Scalar\String_) {
            return [$expr->value];
        }

        if ($recurseArray && $expr instanceof Node\Expr\Array_) {
            $out = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                    $out[] = $item->value->value;
                }
            }

            return $out;
        }

        return [];
    }

    /**
     * @param list<string> $dropped
     */
    private function isRestoredInDown(?Node\Stmt\ClassMethod $down, array $dropped): bool
    {
        if ($down === null || $down->stmts === null) {
            return false;
        }

        $literals = [];
        foreach (
            $this->finder()->find($down->stmts, static function (Node $node): bool {
                return $node instanceof Node\Scalar\String_;
            }) as $node
        ) {
            if ($node instanceof Node\Scalar\String_) {
                $literals[] = $node->value;
            }
        }

        foreach ($dropped as $name) {
            if (!in_array($name, $literals, true)) {
                return false;
            }
        }

        return true;
    }
}
