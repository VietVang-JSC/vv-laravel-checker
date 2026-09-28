<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Function-scope resolution shared by all data-flow consumers.
 *
 * Scopes are enclosing ClassMethod/Function_ nodes identified by
 * spl_object_id(); top-level code is scope 0. Closures do not open a
 * scope — their nodes belong to the enclosing function, matching how
 * PHP executes them.
 */
final class ScopeResolver
{
    private NodeFinder $finder;

    public function __construct(?NodeFinder $finder = null)
    {
        $this->finder = $finder ?? new NodeFinder();
    }

    /**
     * spl_object_id of the enclosing function, 0 for top-level code.
     *
     * @param list<Node> $nodes
     */
    public function funcId(Node $node, array $nodes): int
    {
        $target = spl_object_id($node);
        foreach ($this->functions($nodes) as $id => $func) {
            $found = $this->finder->find($func, static function (Node $inner) use ($target): bool {
                return spl_object_id($inner) === $target;
            });
            if ($found !== []) {
                return $id;
            }
        }

        return 0;
    }

    /**
     * @param list<Node> $nodes
     * @return array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_>
     */
    public function functions(array $nodes): array
    {
        $out = [];
        foreach (
            $this->finder->find($nodes, static function (Node $inner): bool {
                return $inner instanceof Node\Stmt\ClassMethod || $inner instanceof Node\Stmt\Function_;
            }) as $func
        ) {
            if ($func instanceof Node\Stmt\ClassMethod || $func instanceof Node\Stmt\Function_) {
                $out[spl_object_id($func)] = $func;
            }
        }

        return $out;
    }
}
