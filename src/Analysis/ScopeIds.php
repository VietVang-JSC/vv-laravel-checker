<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;

/**
 * Scope identity via canonical parent links (PERF-OPT-3B). O(depth),
 * no tree walk — replaces the per-sink/per-candidate
 * ScopeResolver::funcId() containment storms once callers hold shared
 * facts instead of re-traversing.
 *
 * Equivalence: ScopeResolver::funcId returns the first function (in
 * traversal order) containing the node, else 0. A function's
 * declaration is always visited before anything nested inside it, so
 * "first containing in traversal order" == "outermost ancestor
 * function". Closures open no scope in either implementation. The
 * self-check covers funcId() being called on a function node itself
 * (NodeFinder visits the searched node too).
 */
final class ScopeIds
{
    /**
     * spl_object_id of the outermost enclosing ClassMethod/Function_,
     * 0 for top-level code. Requires canonical parent links.
     */
    public static function outermost(Node $node): int
    {
        $id = 0;
        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
            $id = spl_object_id($node);
        }
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if (
                $parent instanceof Node\Stmt\ClassMethod
                || $parent instanceof Node\Stmt\Function_
            ) {
                $id = spl_object_id($parent);
            }
            $current = $parent;
        }

        return $id;
    }

    /**
     * Subtree containment via parent links (O(depth), no tree walk).
     */
    public static function isWithin(Node $node, Node $ancestor): bool
    {
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if ($parent === $ancestor) {
                return true;
            }
            $current = $parent;
        }

        return false;
    }
}
