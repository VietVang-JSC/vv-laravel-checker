<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;

/**
 * Variable-origin maps shared by all data-flow consumers.
 *
 * Two views over the same assignments:
 * - origins(): every assignment anywhere (unordered). Backward compatible
 *   with the old file-wide scans; answers "where COULD this value come
 *   from" — silencing direction only.
 * - visible(): straight-line assignments in the same scope, above a line,
 *   in source order. Answers "what DOES this value hold here" for sinks.
 *   Conditional reassignments never silence — one path may keep taint.
 *
 * Extended origins (foreach values/keys, array-element and $this->property
 * assignments, property defaults) are included: they only ever add
 * origins, so checks built on them stay on the silencing side.
 */
final class AssignmentMap
{
    private NodeFinder $finder;

    private ScopeResolver $scopes;

    public function __construct(?NodeFinder $finder = null, ?ScopeResolver $scopes = null)
    {
        $this->finder = $finder ?? new CountingNodeFinder();
        $this->scopes = $scopes ?? new ScopeResolver($this->finder);
    }

    /**
     * All assignment origins, keyed by variable name. `$this->prop`
     * assignments and property defaults are keyed as `this->prop`.
     *
     * @param list<Node> $nodes
     * @return array<string, list<Node\Expr>>
     */
    public function origins(array $nodes): array
    {
        $origins = [];
        $found = $this->finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Assign
                || $node instanceof Node\Stmt\Foreach_
                || $node instanceof Node\Stmt\Property;
        });
        foreach ($found as $node) {
            if ($node instanceof Node\Expr\Assign) {
                $key = self::targetKey($node->var);
                if ($key !== null) {
                    $origins[$key][] = $node->expr;
                }
                continue;
            }
            if ($node instanceof Node\Stmt\Foreach_) {
                if ($node->valueVar instanceof Node\Expr\Variable && is_string($node->valueVar->name)) {
                    $origins[$node->valueVar->name][] = $node->expr;
                }
                if ($node->keyVar instanceof Node\Expr\Variable && is_string($node->keyVar->name)) {
                    $origins[$node->keyVar->name][] = $node->expr;
                }
                continue;
            }
            if ($node instanceof Node\Stmt\Property) {
                foreach ($node->props as $prop) {
                    if (
                        $prop instanceof Node\Stmt\PropertyProperty
                        && $prop->default instanceof Node\Expr
                    ) {
                        $origins['this->' . $prop->name->toString()][] = $prop->default;
                    }
                }
            }
        }

        return $origins;
    }

    /**
     * Straight-line assignments visible at a sink: same function scope
     * (top-level assigns are visible everywhere), above the sink line,
     * in source order. Anything inside if/try/loops/closures is excluded.
     *
     * @param list<Node> $nodes
     * @return list<Node\Expr\Assign>
     */
    public function visible(array $nodes, int $funcId, int $sinkLine): array
    {
        $funcs = $this->scopes->functions($nodes);

        $out = [];
        $collect = static function (array $stmts) use (&$out, $sinkLine): void {
            foreach ($stmts as $stmt) {
                if (
                    $stmt instanceof Node\Stmt\Expression
                    && $stmt->expr instanceof Node\Expr\Assign
                    && $stmt->expr->var instanceof Node\Expr\Variable
                    && is_string($stmt->expr->var->name)
                    && $stmt->getStartLine() < $sinkLine
                ) {
                    $out[] = $stmt->expr;
                }
            }
        };

        $collect($nodes);
        if ($funcId !== 0 && isset($funcs[$funcId])) {
            $func = $funcs[$funcId];
            if (is_array($func->stmts)) {
                $collect($func->stmts);
            }
        }

        return $out;
    }

    /**
     * Origin key for an assignment target: plain variables by name,
     * `$arr[...] =` by array name, `$this->prop =` / property defaults
     * by `this->prop`. Anything else (destructuring, dynamic names)
     * yields null.
     */
    public static function targetKey(Node\Expr $target): ?string
    {
        if ($target instanceof Node\Expr\Variable && is_string($target->name)) {
            return $target->name;
        }
        if (
            $target instanceof Node\Expr\ArrayDimFetch
            && $target->var instanceof Node\Expr\Variable
            && is_string($target->var->name)
        ) {
            return $target->var->name;
        }
        if (
            $target instanceof Node\Expr\PropertyFetch
            && $target->var instanceof Node\Expr\Variable
            && $target->var->name === 'this'
            && $target->name instanceof Node\Identifier
        ) {
            return 'this->' . $target->name->toString();
        }

        return null;
    }
}
