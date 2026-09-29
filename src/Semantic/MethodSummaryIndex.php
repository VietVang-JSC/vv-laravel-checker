<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

/**
 * Bounded interprocedural return summaries (v0.5.2, shadow mode).
 *
 * One call boundary deep, never a general call graph. Summarizes what a
 * method returns in terms of its parameters (`PARAM(i)` + operation) or
 * as internal/unknown — the call-site applies actual arguments. No
 * interfaces, container dispatch, facades, magic methods, polymorphism,
 * callbacks, or side-effect reasoning; anything beyond the bounded
 * shapes resolves to UNKNOWN with a first-class reason.
 *
 * Performance is instrumented, not optimized: every request, hit,
 * miss, parsed file and cycle is counted so a parse-amplification
 * regression shows up immediately.
 */
final class MethodSummaryIndex
{
    /** @var list<string> */
    private array $files;

    /** @var array<string, MethodSummary> class::method (lower) => summary */
    private array $cache = [];

    /** @var array<string, true> in-progress resolutions (cycle guard) */
    private array $active = [];

    /** @var array<string, list<Node>|null> realpath => AST */
    private array $astCache = [];

    private int $requests = 0;

    private int $hits = 0;

    private int $misses = 0;

    private int $cycles = 0;

    private int $astParses = 0;

    private float $seconds = 0.0;

    /**
     * @param list<string> $files absolute paths (class-file lookup scope)
     */
    public function __construct(array $files = [])
    {
        $this->files = $files;
    }

    /**
     * @return array{requests: int, hits: int, misses: int, methods: int, ast_parses: int, cycles_stopped: int, seconds: float}
     */
    public function stats(): array
    {
        return [
            'requests' => $this->requests,
            'hits' => $this->hits,
            'misses' => $this->misses,
            'methods' => count($this->cache),
            'ast_parses' => $this->astParses,
            'cycles_stopped' => $this->cycles,
            'seconds' => round($this->seconds, 3),
        ];
    }

    public function summary(string $class, string $method): MethodSummary
    {
        $start = microtime(true);
        try {
            return $this->doSummary($class, $method);
        } finally {
            $this->seconds += microtime(true) - $start;
        }
    }

    private function doSummary(string $class, string $method): MethodSummary
    {
        ++$this->requests;
        $key = strtolower(ltrim($class, '\\')) . '::' . strtolower($method);
        if (isset($this->cache[$key])) {
            ++$this->hits;

            return $this->cache[$key];
        }
        ++$this->misses;
        if (isset($this->active[$key])) {
            ++$this->cycles;

            return MethodSummary::unknown($class, $method, 'cycle');
        }
        $this->active[$key] = true;
        try {
            $summary = $this->buildSummary($class, $method);
        } finally {
            unset($this->active[$key]);
        }
        $this->cache[$key] = $summary;

        return $summary;
    }

    /**
     * Method lookup starting at the parent: implements `parent::method()`
     * semantics (private ancestors ARE reachable through parent::).
     */
    public function parentSummary(string $callerClass, string $method): MethodSummary
    {
        $start = microtime(true);
        try {
            $loc = $this->locateClass($callerClass);
            if ($loc === null) {
                return MethodSummary::unknown($callerClass, $method, 'unresolved-class');
            }
            $parent = $this->extendsName($loc['node'], $loc['uses'], $loc['namespace']);
            if ($parent === null) {
                return MethodSummary::unknown($callerClass, $method, 'unresolved-parent');
            }

            return $this->resolveInHierarchy($parent, $method, $callerClass, 0, true);
        } finally {
            $this->seconds += microtime(true) - $start;
        }
    }

    private function buildSummary(string $class, string $method): MethodSummary
    {
        return $this->resolveInHierarchy($class, $method, $class, 0, false);
    }

    private const MAX_CHAIN = 8;

    /**
     * Class-hierarchy method lookup: nearest definition wins (child
     * overrides), private ancestors are skipped (never inherited —
     * except through an explicit `parent::` call), abstract/interface
     * machinery stays out of scope.
     */
    private function resolveInHierarchy(
        string $class,
        string $method,
        string $origin,
        int $depth,
        bool $viaParentCall
    ): MethodSummary {
        if ($depth > self::MAX_CHAIN) {
            return MethodSummary::unknown($origin, $method, 'depth-limit');
        }
        $loc = $this->locateClass($class);
        if ($loc === null) {
            return MethodSummary::unknown($origin, $method, 'unresolved-class');
        }
        $target = $this->findMethodInClass($loc['node'], $method);
        if ($target !== null) {
            $visibility = $target->isPrivate() ? 'private' : ($target->isProtected() ? 'protected' : 'public');
            if ($visibility === 'private' && $class !== $origin && !$viaParentCall) {
                // Private members are not inherited: keep walking up.
                $parent = $this->extendsName($loc['node'], $loc['uses'], $loc['namespace']);
                if ($parent === null) {
                    return MethodSummary::unknown($origin, $method, 'unresolved-method');
                }

                return $this->resolveInHierarchy($parent, $method, $origin, $depth + 1, $viaParentCall);
            }

            return $this->summarizeMethod($target, $class, $method, $visibility);
        }
        $parent = $this->extendsName($loc['node'], $loc['uses'], $loc['namespace']);
        if ($parent === null) {
            return MethodSummary::unknown($origin, $method, 'unresolved-method');
        }

        return $this->resolveInHierarchy($parent, $method, $origin, $depth + 1, $viaParentCall);
    }

    /**
     * @return array{node: Node\Stmt\Class_, uses: array<string, string>, namespace: string|null, file: string}|null
     */
    private function locateClass(string $class): ?array
    {
        $file = $this->classFile($class);
        if ($file === null) {
            return null;
        }
        $nodes = $this->astOf($file);
        if ($nodes === null) {
            return null;
        }
        $short = $this->shortClass($class);
        $namespace = $this->namespaceOf($nodes);
        $finder = new NodeFinder();
        $best = null;
        foreach ($finder->find($nodes, static fn (Node $n): bool => $n instanceof Node\Stmt\Class_) as $node) {
            if (!$node instanceof Node\Stmt\Class_ || $node->name === null) {
                continue;
            }
            if (strtolower($node->name->toString()) !== strtolower($short)) {
                continue;
            }
            $best = $node;
            if ($namespace !== null && strtolower($namespace) === strtolower(ltrim($this->namespacePrefix($class), '\\'))) {
                break;
            }
        }
        if ($best === null) {
            return null;
        }

        return ['node' => $best, 'uses' => $this->useMap($nodes), 'namespace' => $namespace, 'file' => $file];
    }

    private function namespacePrefix(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? '' : substr($trimmed, 0, $pos);
    }

    /**
     * @param array<string, string> $uses
     */
    private function extendsName(Node\Stmt\Class_ $node, array $uses, ?string $namespace): ?string
    {
        if (!$node->extends instanceof Node\Name) {
            return null;
        }

        return $this->resolveName($node->extends->toString(), $uses, $namespace, $node->extends);
    }

    /**
     * @param array<string, string> $uses
     */
    private function resolveName(string $name, array $uses, ?string $namespace, ?Node\Name $node = null): string
    {
        if ($node instanceof Node\Name\FullyQualified) {
            return $node->toString();
        }
        if (str_starts_with($name, '\\')) {
            return ltrim($name, '\\');
        }
        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            if (isset($uses[$first])) {
                return $uses[$first] . substr($name, $pos);
            }

            return $namespace !== null ? $namespace . '\\' . $name : $name;
        }
        $lower = strtolower($name);
        if (isset($uses[$lower])) {
            return $uses[$lower];
        }

        return $namespace !== null ? $namespace . '\\' . $name : $name;
    }

    private function findMethodInClass(Node\Stmt\Class_ $node, string $method): ?Node\Stmt\ClassMethod
    {
        foreach ($node->stmts as $stmt) {
            if (
                $stmt instanceof Node\Stmt\ClassMethod
                && strtolower($stmt->name->toString()) === strtolower($method)
            ) {
                return $stmt;
            }
        }

        return null;
    }

    private function summarizeMethod(
        Node\Stmt\ClassMethod $target,
        string $declaringClass,
        string $method,
        string $visibility
    ): MethodSummary {
        // Preserve the original request class in provenance while the
        // declaring class travels separately.
        $summary = $this->summarizeBody($target, $declaringClass, $method);
        if ($summary->kind === MethodSummary::UNKNOWN) {
            return MethodSummary::unknown(
                $summary->class,
                $summary->method,
                $summary->unresolvedReason ?? 'unsupported-expression',
                $declaringClass,
                $visibility
            );
        }

        return new MethodSummary(
            $summary->class,
            $summary->method,
            $summary->kind,
            $summary->params,
            $summary->paramIndex,
            $summary->operation,
            $summary->fields,
            $summary->confidence,
            $summary->evidence,
            null,
            $declaringClass,
            $visibility
        );
    }
    private function summarizeBody(
        Node\Stmt\ClassMethod $target,
        string $class,
        string $method
    ): MethodSummary {
        if ($target->stmts === null) {
            return MethodSummary::unknown($class, $method, 'unsupported-expression');
        }
        $params = [];
        foreach ($target->params as $param) {
            if ($param instanceof Node\Param && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                $params[] = $param->var->name;
            } else {
                $params[] = '';
            }
        }
        $finder = new NodeFinder();
        $returns = $finder->find($target->stmts, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Return_;
        });
        if ($returns === []) {
            return MethodSummary::unknown($class, $method, 'unsupported-expression');
        }
        $summarized = [];
        foreach ($returns as $ret) {
            if (!$ret instanceof Node\Stmt\Return_) {
                continue;
            }
            $summarized[] = $this->summarizeReturn($ret->expr, $params, $class, $method);
        }
        // Identical provenances merge; anything mixed stays unknown.
        $first = $summarized[0];
        foreach ($summarized as $candidate) {
            if (
                $candidate['kind'] !== $first['kind']
                || $candidate['param'] !== $first['param']
                || $candidate['op'] !== $first['op']
                || $candidate['fields'] !== $first['fields']
            ) {
                return MethodSummary::unknown($class, $method, 'mixed-return-provenance');
            }
            if ($candidate['kind'] === MethodSummary::UNKNOWN) {
                return MethodSummary::unknown($class, $method, $candidate['reason'] ?? 'unsupported-expression');
            }
        }

        return new MethodSummary(
            $class,
            $method,
            $first['kind'],
            $params,
            $first['param'],
            $first['op'],
            $first['fields'],
            'high',
            $first['evidence'],
            null
        );
    }

    /**
     * @param list<string> $params
     * @return array{kind: string, param: int|null, op: string|null, fields: list<string>|null, evidence: string, reason: string|null}
     */
    private function summarizeReturn(
        ?Node\Expr $expr,
        array $params,
        string $class,
        string $method
    ): array {
        $unknown = static fn (string $reason): array => [
            'kind' => MethodSummary::UNKNOWN, 'param' => null, 'op' => null,
            'fields' => null, 'evidence' => '', 'reason' => $reason,
        ];
        if ($expr === null) {
            return ['kind' => MethodSummary::INTERNAL, 'param' => null, 'op' => null, 'fields' => null, 'evidence' => 'bare return', 'reason' => null];
        }
        if ($expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_ || $expr instanceof Node\Expr\ConstFetch) {
            return ['kind' => MethodSummary::INTERNAL, 'param' => null, 'op' => null, 'fields' => null, 'evidence' => 'literal return', 'reason' => null];
        }
        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if (!$item instanceof Node\Expr\ArrayItem || !$item->value instanceof Node\Scalar\String_) {
                    return $unknown('unsupported-expression');
                }
            }

            return ['kind' => MethodSummary::INTERNAL, 'param' => null, 'op' => null, 'fields' => null, 'evidence' => 'literal array return', 'reason' => null];
        }
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $index = array_search($expr->name, $params, true);
            if ($index !== false) {
                return [
                    'kind' => MethodSummary::PARAM, 'param' => (int) $index,
                    'op' => MethodSummary::OP_PASSTHROUGH, 'fields' => null,
                    'evidence' => 'return $' . $expr->name, 'reason' => null,
                ];
            }

            return $unknown('unsupported-expression');
        }
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $op = strtolower($expr->name->toString());
            $mapped = match ($op) {
                'all' => MethodSummary::OP_ALL,
                'input' => MethodSummary::OP_INPUT,
                'only' => MethodSummary::OP_ONLY,
                'except' => MethodSummary::OP_EXCEPT,
                'validated' => MethodSummary::OP_VALIDATED,
                'safe' => MethodSummary::OP_SAFE,
                default => null,
            };
            if ($mapped === null) {
                // Any other call in return position needs a nested
                // summary — out of bounded depth-1 scope.
                return $unknown('nested-call');
            }
            // Receiver must be exactly a parameter (any other receiver —
            // nested calls, services, statics — is out of bounded scope).
            if (!$expr->var instanceof Node\Expr\Variable || !is_string($expr->var->name)) {
                return $unknown('nested-call');
            }
            $index = array_search($expr->var->name, $params, true);
            if ($index === false) {
                return $unknown('unsupported-expression');
            }
            $fields = null;
            if (in_array($mapped, [MethodSummary::OP_ONLY, MethodSummary::OP_EXCEPT], true)) {
                $fields = $this->literalStringList($expr);
                if ($fields === null) {
                    return $unknown('unsupported-expression');
                }
            }

            return [
                'kind' => MethodSummary::PARAM, 'param' => (int) $index,
                'op' => $mapped, 'fields' => $fields,
                'evidence' => 'return $' . $expr->var->name . '->' . $op . '()',
                'reason' => null,
            ];
        }

        return $unknown($expr instanceof Node\Expr\FuncCall ? 'nested-call' : 'unsupported-expression');
    }

    /**
     * @return list<string>|null literal string list, null when dynamic
     */
    private function literalStringList(Node\Expr\MethodCall $expr): ?array
    {
        $arg = $expr->args[0] ?? null;
        if (!$arg instanceof Node\Arg || !$arg->value instanceof Node\Expr\Array_) {
            return null;
        }
        $fields = [];
        foreach ($arg->value->items as $item) {
            if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                $fields[] = $item->value->value;
                continue;
            }

            return null;
        }

        return $fields;
    }

    /**
     * @param list<Node> $nodes
     * @return array<string, string> lowercase alias => FQCN
     */
    private function useMap(array $nodes): array
    {
        $map = [];
        $finder = new NodeFinder();
        $imports = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Use_ || $node instanceof Node\Stmt\GroupUse;
        });
        foreach ($imports as $import) {
            if ($import instanceof Node\Stmt\GroupUse) {
                foreach ($import->uses as $use) {
                    if (!$use instanceof Node\Stmt\UseUse) {
                        continue;
                    }
                    $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                    $map[strtolower($alias)] = $import->prefix->toString() . '\\' . $use->name->toString();
                }
                continue;
            }
            if (!$import instanceof Node\Stmt\Use_ || $import->type !== Node\Stmt\Use_::TYPE_NORMAL) {
                continue;
            }
            foreach ($import->uses as $use) {
                if (!$use instanceof Node\Stmt\UseUse) {
                    continue;
                }
                $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                $map[strtolower($alias)] = $use->name->toString();
            }
        }

        return $map;
    }

    /**
     * @param list<Node> $nodes
     */
    private function namespaceOf(array $nodes): ?string
    {
        $finder = new NodeFinder();
        $found = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Namespace_;
        });
        foreach ($found as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }

    /**
     * @return list<Node>|null
     */
    private function astOf(string $file): ?array
    {
        $real = realpath($file) ?: $file;
        if (array_key_exists($real, $this->astCache)) {
            return $this->astCache[$real];
        }
        ++$this->astParses;
        $code = is_file($real) ? file_get_contents($real) : false;
        if (!is_string($code) || $code === '') {
            $this->astCache[$real] = null;

            return null;
        }
        try {
            $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($code);
        } catch (\Throwable $e) {
            $this->astCache[$real] = null;

            return null;
        }
        $nodes = [];
        if (is_array($ast)) {
            foreach ($ast as $node) {
                if ($node instanceof Node) {
                    $nodes[] = $node;
                }
            }
        }
        $this->astCache[$real] = $nodes;

        return $nodes;
    }

    public function classFile(string $class): ?string
    {
        $short = $this->shortClass($class);
        if ($short === '') {
            return null;
        }
        $fallback = null;
        foreach ($this->files as $file) {
            $normalized = str_replace('\\', '/', $file);
            if (strtolower((string) pathinfo($normalized, PATHINFO_BASENAME)) !== strtolower($short . '.php')) {
                continue;
            }
            $fallback ??= $file;
        }

        return $fallback;
    }

    private function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
