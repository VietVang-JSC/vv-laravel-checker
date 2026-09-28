<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Per-scope guard-call index shared by data-flow consumers.
 *
 * Different rules interpret guards differently (in_array() allow-lists for
 * SSTI, str_starts_with() prefix gates for redirects, *sanitiz*() calls for
 * SSRF) — this class only partitions candidate calls by function scope so
 * a gate in one function never silences a sink in another. What counts as
 * a guard call is the caller's predicate.
 */
final class GuardMap
{
    private NodeFinder $finder;

    private ScopeResolver $scopes;

    public function __construct(?NodeFinder $finder = null, ?ScopeResolver $scopes = null)
    {
        $this->finder = $finder ?? new NodeFinder();
        $this->scopes = $scopes ?? new ScopeResolver($this->finder);
    }

    /**
     * Guard-call nodes per scope (0 = top-level code). A node belongs to
     * exactly one scope: its innermost enclosing function, or top-level
     * when it lives in no function at all.
     *
     * @param list<Node> $nodes
     * @param callable(Node): bool $isGuard
     * @return array<int, list<Node>>
     */
    public function find(array $nodes, callable $isGuard): array
    {
        $funcs = $this->scopes->functions($nodes);

        $out = [];
        $candidates = $this->finder->find($nodes, static function (Node $node) use ($isGuard): bool {
            return $isGuard($node);
        });
        foreach ($candidates as $node) {
            $funcId = 0;
            foreach ($funcs as $id => $func) {
                $target = spl_object_id($node);
                $found = $this->finder->find($func, static function (Node $inner) use ($target): bool {
                    return spl_object_id($inner) === $target;
                });
                if ($found !== []) {
                    $funcId = $id;
                    break;
                }
            }
            $out[$funcId][] = $node;
        }

        return $out;
    }
}
