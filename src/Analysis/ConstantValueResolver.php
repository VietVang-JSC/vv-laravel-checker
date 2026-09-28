<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Bounded constant-expression resolver for the semantic engine.
 *
 * Resolves only deterministic, side-effect-free expressions:
 * string literals, single-assignment variables (`$a = 'x'`, `$b = $a`,
 * `$c = $a . 'y'`), `__DIR__`/`__FILE__`, `base_path()/app_path()/...`
 * helpers with literal arguments, and trivial `Foo::class`.
 *
 * Conservative by construction:
 * - One assignment per variable per scope; any conditional, repeated,
 *   or later assignment makes the variable UNKNOWN (never last-wins).
 * - Assignments must precede the use in source order (no backward
 *   resolution) and live in the same function scope (no leakage across
 *   functions; closures belong to their enclosing function).
 * - Depth cap (16) plus a visited-assignment set stops cycles like
 *   `$a = $b; $b = $a`.
 * - `config()`, `env()`, `request()`, `sprintf()`, method calls and
 *   everything else resolve to null.
 *
 * The last failure reason is exposed for coverage metrics only
 * (diagnostic — callers must treat null as unknown regardless).
 */
final class ConstantValueResolver
{
    private const MAX_DEPTH = 16;

    private ?string $failureReason = null;

    public function failureReason(): ?string
    {
        return $this->failureReason;
    }

    public function resolve(Node\Expr $expr, ConstantScope $scope, int $beforeLine): ?ConstantValue
    {
        $this->failureReason = null;

        return $this->doResolve($expr, $scope, $beforeLine, 0, []);
    }

    /**
     * @param array<int, true> $visited spl_object_id of assignments
     */
    private function doResolve(
        Node\Expr $expr,
        ConstantScope $scope,
        int $beforeLine,
        int $depth,
        array $visited
    ): ?ConstantValue {
        if ($depth > self::MAX_DEPTH) {
            $this->failureReason = 'depth-exceeded';

            return null;
        }
        $step = static fn (string $kind, string $detail, ?int $line = null): array => [
            'kind' => $kind,
            'detail' => $detail,
            'file' => $scope->file,
            'line' => $line,
        ];

        if ($expr instanceof Node\Scalar\String_) {
            return new ConstantValue($expr->value, 'exact', [
                $step('literal', $expr->value, $expr->getStartLine()),
            ]);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $left = $this->doResolve($expr->left, $scope, $beforeLine, $depth + 1, $visited);
            $right = $this->doResolve($expr->right, $scope, $beforeLine, $depth + 1, $visited);
            if ($left === null || $right === null) {
                $this->failureReason ??= 'dynamic-concat';

                return null;
            }

            return new ConstantValue(
                $left->value . $right->value,
                'exact',
                [...$left->provenance, ...$right->provenance, $step('concat', '+', $expr->getStartLine())]
            );
        }

        if ($expr instanceof Node\Scalar\MagicConst\Dir) {
            return new ConstantValue(dirname($scope->file), 'exact', [
                $step('magic', '__DIR__', $expr->getStartLine()),
            ]);
        }
        if ($expr instanceof Node\Scalar\MagicConst\File) {
            return new ConstantValue($scope->file, 'exact', [
                $step('magic', '__FILE__', $expr->getStartLine()),
            ]);
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $this->resolveVariable($expr, $scope, $beforeLine, $depth, $visited);
        }

        if (
            $expr instanceof Node\Expr\ClassConstFetch
            && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'class'
        ) {
            return new ConstantValue(
                $this->resolveName($expr->class->toString(), $scope),
                'exact',
                [$step('class', $expr->class->toString(), $expr->getStartLine())]
            );
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), [
                'base_path', 'app_path', 'database_path', 'resource_path',
                'config_path', 'lang_path', 'public_path', 'storage_path',
            ], true)
        ) {
            $arg = $expr->args[0] ?? null;
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                return new ConstantValue($arg->value->value, 'exact', [
                    $step('helper', strtolower($expr->name->toString()), $expr->getStartLine()),
                ]);
            }
            $this->failureReason = 'dynamic-helper-arg';

            return null;
        }

        $this->failureReason = $this->kindReason($expr);

        return null;
    }

    /**
     * Single-assignment rule: exactly one direct (top-level, same-scope,
     * preceding) assignment and no other assignment to the name in the
     * same scope. Assignments in other functions are a different scope —
     * never leakage, never poison. Anything else is UNKNOWN.
     *
     * @param array<int, true> $visited
     */
    private function resolveVariable(
        Node\Expr\Variable $var,
        ConstantScope $scope,
        int $beforeLine,
        int $depth,
        array $visited
    ): ?ConstantValue {
        $name = $var->name;
        if (!is_string($name)) {
            $this->failureReason = 'dynamic-variable';

            return null;
        }
        $finder = new NodeFinder();
        $scopes = new ScopeResolver($finder);
        $funcs = $scopes->functions($scope->nodes);

        // Own top-level statement list: file scope, or the enclosing
        // function body. Never both — a function body does not see
        // file-level locals.
        $own = $scope->nodes;
        if ($scope->funcId !== 0) {
            if (!isset($funcs[$scope->funcId]) || !is_array($funcs[$scope->funcId]->stmts)) {
                $this->failureReason = 'unsupported-scope';

                return null;
            }
            $own = $funcs[$scope->funcId]->stmts;
        }

        // Enclosing closures contribute their body top-level lists too:
        // a group callback (`Route::group(..., function () { $p = 'x';
        // Route::get($p, ...); })`) runs once at registration, so
        // straight-line order holds inside it. Innermost first.
        $lists = [$own];
        foreach ($this->enclosingClosures($var, $scope->nodes) as $closure) {
            if (is_array($closure->stmts)) {
                array_unshift($lists, $closure->stmts);
            }
        }

        // Direct candidates: Expression assigns across the own lists.
        $direct = [];
        foreach ($lists as $stmts) {
            foreach ($stmts as $stmt) {
                if (
                    $stmt instanceof Node\Stmt\Expression
                    && $stmt->expr instanceof Node\Expr\Assign
                    && $stmt->expr->var instanceof Node\Expr\Variable
                    && $stmt->expr->var->name === $name
                ) {
                    $direct[] = $stmt->expr;
                }
            }
        }
        $directIds = [];
        foreach ($direct as $assign) {
            $directIds[spl_object_id($assign)] = true;
        }

        // Any other assignment to the name in the SAME scope (nested in
        // if/try/loops) poisons the proof. Other function scopes are
        // irrelevant, never poison.
        $all = $finder->find($scope->nodes, static function (Node $node) use ($name): bool {
            return $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === $name;
        });
        foreach ($all as $assign) {
            if (isset($directIds[spl_object_id($assign)])) {
                continue;
            }
            if ($scopes->funcId($assign, $scope->nodes) !== $scope->funcId) {
                continue;
            }
            $this->failureReason = 'conditional-assignment';

            return null;
        }

        if (count($direct) === 0) {
            $this->failureReason = 'unassigned-variable';

            return null;
        }
        if (count($direct) > 1) {
            $this->failureReason = 'ambiguous-assignment';

            return null;
        }
        $assign = $direct[0];
        if ($assign->getStartLine() >= $beforeLine) {
            $this->failureReason = 'use-before-assign';

            return null;
        }
        if (isset($visited[spl_object_id($assign)])) {
            $this->failureReason = 'cyclic-assignment';

            return null;
        }
        $visited[spl_object_id($assign)] = true;

        $value = $this->doResolve($assign->expr, $scope, $beforeLine, $depth + 1, $visited);
        if ($value === null) {
            return null;
        }

        return $value->withStep([
            'kind' => 'variable',
            'detail' => '$' . $name,
            'file' => $scope->file,
            'line' => $assign->getStartLine(),
        ]);
    }

    private function resolveName(string $name, ConstantScope $scope): string
    {
        if ($name !== '' && $name[0] === '\\') {
            return ltrim($name, '\\');
        }
        // FullyQualified::toString() drops the leading backslash, so a
        // single-segment-or-dotted name here is always relative.
        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            if (isset($scope->uses[$first])) {
                return $scope->uses[$first] . substr($name, $pos);
            }

            return $scope->namespace !== null ? $scope->namespace . '\\' . $name : $name;
        }
        $lower = strtolower($name);
        if (isset($scope->uses[$lower])) {
            return $scope->uses[$lower];
        }

        return $scope->namespace !== null ? $scope->namespace . '\\' . $name : $name;
    }

    /**
     * Closures enclosing the use-site, innermost first. Their body
     * top-level lists extend visibility (registration callbacks run
     * once, in order).
     *
     * @param list<Node> $nodes
     * @return list<Node\Expr\Closure>
     */
    private function enclosingClosures(Node $target, array $nodes): array
    {
        $chain = $this->ancestorChain($target, $nodes);
        if ($chain === null) {
            return [];
        }
        $out = [];
        foreach (array_reverse($chain) as $ancestor) {
            if ($ancestor instanceof Node\Expr\Closure) {
                $out[] = $ancestor;
            }
        }

        return $out;
    }

    /**
     * @param list<Node> $nodes
     * @return list<Node>|null ancestor chain, outermost first
     */
    private function ancestorChain(Node $target, array $nodes): ?array
    {
        $id = spl_object_id($target);
        foreach ($nodes as $node) {
            if (spl_object_id($node) === $id) {
                return [];
            }
            foreach ($node->getSubNodeNames() as $sub) {
                $child = $node->$sub;
                $children = is_array($child) ? array_values($child) : [$child];
                foreach ($children as $item) {
                    if (!$item instanceof Node) {
                        continue;
                    }
                    if (spl_object_id($item) === $id) {
                        return [$node];
                    }
                    $deeper = $this->ancestorChain($target, [$item]);
                    if ($deeper !== null) {
                        return [$node, ...$deeper];
                    }
                }
            }
        }

        return null;
    }

    private function kindReason(Node\Expr $expr): string
    {
        if ($expr instanceof Node\Expr\FuncCall) {
            return 'function-call';
        }
        if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
            return 'method-call';
        }
        if ($expr instanceof Node\Expr\Variable) {
            return 'dynamic-variable';
        }
        if (
            $expr instanceof Node\Expr\PropertyFetch
            || $expr instanceof Node\Expr\ArrayDimFetch
            || $expr instanceof Node\Expr\Ternary
        ) {
            return 'dynamic-expression';
        }

        return 'unsupported-expression';
    }
}
