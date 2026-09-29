<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Shared structural fact index (PERF-OPT-3). One indexing traversal per
 * file answers "where are the interesting nodes?" for every analyzer —
 * replacing the N× full-tree re-traversals (node amplification 136x in
 * PERF-EVAL-2) with a single pass whose buckets hold CANONICAL node
 * references (no copies, no wrappers, no interpretation).
 *
 * Hard boundary: structural only. "What does this mean in this flow?"
 * stays in AssignmentMap / GuardMap / ScopeResolver; "is this a
 * vulnerability?" stays in the analyzers. A fact is indexed only when
 * >= 2 analyzers need it or one expensive analyzer uses it at volume.
 * Dynamic identifiers are never guessed — only statically-known names
 * are bucketed by name (and 3A does not even need those yet).
 *
 * Lazy per file (mirrors ScanContext): untouched files cost nothing.
 * Build wall time is reported as the `fact-index-build` phase.
 */
final class StructuralFactIndex implements ScanContextAware
{
    use ScanContextTrait;

    /** @var array<string, list<Node\Expr\FuncCall|Node\Expr\MethodCall|Node\Expr\StaticCall>> realpath => calls */
    private array $calls = [];

    /** @var array<string, list<Node\Stmt\ClassMethod|Node\Stmt\Function_>> realpath => functions */
    private array $functions = [];

    /** @var array<string, list<Node\Expr\Assign|Node\Stmt\If_>> realpath => assigns and ifs */
    private array $assignsAndIfs = [];

    /** @var array<string, true> realpath => built (even when empty) */
    private array $built = [];

    /**
     * All call expressions in traversal order — the same set (and order)
     * a `find($ast, FuncCall|MethodCall|StaticCall)` would return.
     *
     * @param list<Node>|null $nodes pre-fetched tree (avoids a second
     *   sharedAst lookup when the caller already holds it)
     * @return list<Node\Expr\FuncCall|Node\Expr\MethodCall|Node\Expr\StaticCall>
     */
    public function calls(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->calls[$this->key($file)] ?? [];
    }

    /**
     * ClassMethod/Function_ nodes in traversal order — the same set
     * ScopeResolver::functions() returns (ids are spl_object_id, so
     * order only matters for iteration stability).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Stmt\ClassMethod|Node\Stmt\Function_>
     */
    public function functions(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->functions[$this->key($file)] ?? [];
    }

    /**
     * Assign + If_ nodes in traversal order (guard/sanitizer scans).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Expr\Assign|Node\Stmt\If_>
     */
    public function assignsAndIfs(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->assignsAndIfs[$this->key($file)] ?? [];
    }

    /**
     * @param list<Node>|null $nodes
     */
    private function ensure(string $file, ?array $nodes = null): void
    {
        $key = $this->key($file);
        if (isset($this->built[$key])) {
            return;
        }
        $this->built[$key] = true;
        $nodes ??= $this->sharedAst($file);
        if ($nodes === null) {
            return;
        }
        $start = microtime(true);
        // Plain NodeFinder: the indexing pass itself is timed as
        // `fact-index-build`, not attributed as analyzer traversals.
        $found = (new NodeFinder())->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Stmt\ClassMethod
                || $node instanceof Node\Stmt\Function_
                || $node instanceof Node\Expr\Assign
                || $node instanceof Node\Stmt\If_;
        });
        $calls = [];
        $functions = [];
        $assigns = [];
        foreach ($found as $node) {
            if (
                $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall
            ) {
                $calls[] = $node;
            } elseif ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
                $functions[] = $node;
            } elseif ($node instanceof Node\Expr\Assign || $node instanceof Node\Stmt\If_) {
                $assigns[] = $node;
            }
        }
        $this->calls[$key] = $calls;
        $this->functions[$key] = $functions;
        $this->assignsAndIfs[$key] = $assigns;
        Profiler::add('fact-index-build', microtime(true) - $start);
    }

    private function key(string $file): string
    {
        return realpath($file) ?: $file;
    }
}
