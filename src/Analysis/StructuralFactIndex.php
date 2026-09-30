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

    /**
     * All call expressions in traversal order (FuncCall, MethodCall,
     * NullsafeMethodCall, StaticCall, New_). Type-filtered views below
     * preserve this order.
     *
     * @var array<string, list<Node\Expr>>
     */
    private array $callsAny = [];

    /** @var array<string, list<Node\Stmt\ClassMethod|Node\Stmt\Function_>> realpath => functions */
    private array $functions = [];

    /** @var array<string, list<Node\Expr\Assign|Node\Stmt\If_>> realpath => assigns and ifs */
    private array $assignsAndIfs = [];

    /** @var array<string, list<Node\Stmt\Foreach_>> realpath => foreaches (origins) */
    private array $foreaches = [];

    /** @var array<string, list<Node\Stmt\Property>> realpath => properties (origins) */
    private array $properties = [];

    /** @var array<string, list<Node\Stmt\Use_>> realpath => use statements */
    private array $uses = [];

    /** @var array<string, list<Node\Stmt\Namespace_>> realpath => namespaces */
    private array $namespaces = [];

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
        $out = [];
        foreach ($this->callsAny($file, $nodes) as $node) {
            if (
                $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall
            ) {
                $out[] = $node;
            }
        }

        return $out;
    }

    /**
     * Combined call list incl. nullsafe calls and instantiations, in
     * traversal order (SSRF sink discovery needs all five shapes in one
     * ordered pass).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Expr>
     */
    public function callsAny(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->callsAny[$this->key($file)] ?? [];
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
     * Foreach nodes in traversal order (origin maps).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Stmt\Foreach_>
     */
    public function foreaches(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->foreaches[$this->key($file)] ?? [];
    }

    /**
     * Property declarations in traversal order (origin maps).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Stmt\Property>
     */
    public function properties(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->properties[$this->key($file)] ?? [];
    }

    /**
     * Use statements in traversal order (import maps).
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Stmt\Use_>
     */
    public function uses(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->uses[$this->key($file)] ?? [];
    }

    /**
     * Namespace declarations in traversal order.
     *
     * @param list<Node>|null $nodes
     * @return list<Node\Stmt\Namespace_>
     */
    public function namespaces(string $file, ?array $nodes = null): array
    {
        $this->ensure($file, $nodes);

        return $this->namespaces[$this->key($file)] ?? [];
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
                || $node instanceof Node\Expr\NullsafeMethodCall
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\New_
                || $node instanceof Node\Stmt\ClassMethod
                || $node instanceof Node\Stmt\Function_
                || $node instanceof Node\Expr\Assign
                || $node instanceof Node\Stmt\If_
                || $node instanceof Node\Stmt\Foreach_
                || $node instanceof Node\Stmt\Property
                || $node instanceof Node\Stmt\Use_
                || $node instanceof Node\Stmt\Namespace_;
        });
        $calls = [];
        $functions = [];
        $assigns = [];
        $foreaches = [];
        $properties = [];
        $uses = [];
        $namespaces = [];
        foreach ($found as $node) {
            if (
                $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\NullsafeMethodCall
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\New_
            ) {
                $calls[] = $node;
            } elseif ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
                $functions[] = $node;
            } elseif ($node instanceof Node\Expr\Assign || $node instanceof Node\Stmt\If_) {
                $assigns[] = $node;
            } elseif ($node instanceof Node\Stmt\Foreach_) {
                $foreaches[] = $node;
            } elseif ($node instanceof Node\Stmt\Property) {
                $properties[] = $node;
            } elseif ($node instanceof Node\Stmt\Use_) {
                $uses[] = $node;
            } elseif ($node instanceof Node\Stmt\Namespace_) {
                $namespaces[] = $node;
            }
        }
        $this->callsAny[$key] = $calls;
        $this->functions[$key] = $functions;
        $this->assignsAndIfs[$key] = $assigns;
        $this->foreaches[$key] = $foreaches;
        $this->properties[$key] = $properties;
        $this->uses[$key] = $uses;
        $this->namespaces[$key] = $namespaces;
        Profiler::add('fact-index-build', microtime(true) - $start);
    }

    private function key(string $file): string
    {
        return realpath($file) ?: $file;
    }
}
