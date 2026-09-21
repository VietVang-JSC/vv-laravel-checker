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
 *  - destructive schema operations in `up()` (dropTable, dropColumn, delete
 *    of a whole table without a re-creation path)
 *
 * Assumes: only files under a `/database/migrations/` path segment are considered.
 * Reversibility is a best-effort heuristic, so confidence is medium.
 */
final class MigrationAnalyzer extends AbstractAnalyzer
{
    private const RULE_MISSING_DOWN = 'MIGRATION_MISSING_DOWN';
    private const RULE_DESTRUCTIVE_UP = 'MIGRATION_DESTRUCTIVE_UP';

    private const DESTRUCTIVE_METHODS = [
        'dropTable', 'dropIfExists', 'dropColumn', 'dropForeign', 'dropPrimary',
        'dropIndex', 'dropUnique', 'dropTimestamps', 'delete',
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

        if ($up !== null && $up->stmts !== null && $this->hasDestructiveCall($up->stmts)) {
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

        return $issues;
    }

    /**
     * @param array<Node\Stmt> $stmts
     */
    private function hasDestructiveCall(array $stmts): bool
    {
        $found = $this->finder()->find($stmts, function (Node $node): bool {
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array($node->name->toString(), self::DESTRUCTIVE_METHODS, true);
            }

            return false;
        });

        return $found !== [];
    }
}
