<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Profiling\Profiler;

/**
 * Measurement-only NodeFinder (PERF-EVAL-2). Identical traversal
 * semantics to the parent — instanceof/first variants delegate to
 * find()/findFirst() internally, so wrapping those two covers all four
 * entry points. The filter wrapper counts exactly the nodes tested;
 * with the profiler off this class delegates untouched (one boolean
 * check per call, no per-node cost).
 */
final class CountingNodeFinder extends NodeFinder
{
    /**
     * @param Node|list<Node> $nodes
     * @param callable(Node): bool $filter
     * @return list<Node>
     */
    public function find($nodes, callable $filter): array
    {
        if (!Profiler::isEnabled()) {
            return parent::find($nodes, $filter);
        }
        $visited = 0;
        $wrapped = static function (Node $node) use ($filter, &$visited): bool {
            ++$visited;

            return $filter($node);
        };
        $found = parent::find($nodes, $wrapped);
        Profiler::countTraversal($visited);

        return $found;
    }

    /**
     * @param Node|list<Node> $nodes
     * @param callable(Node): bool $filter
     */
    public function findFirst($nodes, callable $filter): ?Node
    {
        if (!Profiler::isEnabled()) {
            return parent::findFirst($nodes, $filter);
        }
        $visited = 0;
        $wrapped = static function (Node $node) use ($filter, &$visited): bool {
            ++$visited;

            return $filter($node);
        };
        $found = parent::findFirst($nodes, $wrapped);
        Profiler::countTraversal($visited);

        return $found;
    }
}
