<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Best-effort model type for an authorization subject expression
 * (`$this->authorize('update', $post)` → `App\Models\Post`). Bounded:
 * method parameter type-hints, single straight-line assignments from
 * `Model::...` / `new Model`, and one variable hop. Anything else —
 * properties, dynamic expressions, repeated or conditional assignments —
 * resolves to null (medium evidence downstream, never a guess).
 */
final class ModelTypeResolver
{
    /**
     * @param array<string, string> $uses
     */
    public static function resolve(
        Node\Expr $expr,
        Node\Stmt\ClassMethod $method,
        array $uses,
        ?string $namespace,
        int $useLine
    ): ?string {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return self::resolveVariable($expr->name, $method, $uses, $namespace, $useLine, 0);
        }
        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            return self::resolveName($expr->class->toString(), $uses, $namespace);
        }

        return null;
    }

    /**
     * @param array<string, string> $uses
     */
    private static function resolveVariable(
        string $name,
        Node\Stmt\ClassMethod $method,
        array $uses,
        ?string $namespace,
        int $useLine,
        int $depth
    ): ?string {
        if ($depth > 1) {
            return null;
        }
        // Parameter type-hints first (route-model binding included).
        foreach ($method->params as $param) {
            if (
                $param instanceof Node\Param
                && $param->var instanceof Node\Expr\Variable
                && $param->var->name === $name
                && $param->type instanceof Node\Name
                && !self::isBuiltin($param->type->toString())
            ) {
                return self::resolveName($param->type->toString(), $uses, $namespace);
            }
        }
        if ($method->stmts === null) {
            return null;
        }
        // Exactly one straight-line assignment above the use.
        $finder = new NodeFinder();
        $assigns = $finder->find($method->stmts, static function (Node $node) use ($name): bool {
            return $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === $name;
        });
        if (count($assigns) !== 1) {
            return null;
        }
        $assign = $assigns[0];
        if (!$assign instanceof Node\Expr\Assign || $assign->getStartLine() >= $useLine) {
            return null;
        }
        $rhs = $assign->expr;
        if ($rhs instanceof Node\Expr\StaticCall && $rhs->class instanceof Node\Name) {
            return self::resolveName($rhs->class->toString(), $uses, $namespace);
        }
        if ($rhs instanceof Node\Expr\New_ && $rhs->class instanceof Node\Name) {
            return self::resolveName($rhs->class->toString(), $uses, $namespace);
        }
        if ($rhs instanceof Node\Expr\Variable && is_string($rhs->name)) {
            return self::resolveVariable($rhs->name, $method, $uses, $namespace, $useLine, $depth + 1);
        }

        return null;
    }

    /**
     * @param array<string, string> $uses
     */
    private static function resolveName(string $name, array $uses, ?string $namespace): string
    {
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

    private static function isBuiltin(string $name): bool
    {
        return in_array(strtolower($name), [
            'int', 'float', 'string', 'bool', 'array', 'object',
            'callable', 'iterable', 'mixed', 'void', 'null', 'false',
            'true', 'never', 'self', 'static', 'parent',
        ], true);
    }
}
