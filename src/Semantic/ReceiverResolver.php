<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Bounded receiver resolution for interprocedural calls: prove the
 * class behind `$this->service`, `$svc`, `$this`, `self` and friends.
 * Only statically provable types resolve:
 * - promoted constructor params (`private UserService $service`)
 * - typed property declarations (`private UserService $service;`)
 * - constructor `$this->x = $param` with a typed parameter (bounded DI)
 * - `new X`, `app(X::class)` / `resolve(X::class)` with literal classes
 * - local variables with a single straight-line `new X` assignment
 *
 * Untyped properties, `app($dynamic)`, container bindings, facades,
 * traits, magic methods and dynamic dispatch stay UNKNOWN. Name
 * matching alone never resolves (case H).
 */
final class ReceiverResolver
{
    /**
     * @param array<string, string> $uses
     * @return array{class: string}|null
     */
    public static function resolve(
        Node\Expr $receiver,
        Node\Stmt\ClassMethod $caller,
        Node\Stmt\Class_ $callerClass,
        array $uses,
        ?string $namespace
    ): ?array {
        // $this.
        if ($receiver instanceof Node\Expr\Variable && $receiver->name === 'this') {
            return self::classOf($callerClass, $namespace);
        }

        // $this->service: property type via promotion, declaration, or
        // constructor assignment.
        if (
            $receiver instanceof Node\Expr\PropertyFetch
            && $receiver->name instanceof Node\Identifier
            && $receiver->var instanceof Node\Expr\Variable
            && $receiver->var->name === 'this'
        ) {
            $type = self::propertyType($receiver->name->toString(), $callerClass, $uses, $namespace);
            if ($type === null) {
                return null;
            }

            return ['class' => $type];
        }

        // $svc = new X / app(X::class) / single straight-line assign.
        if ($receiver instanceof Node\Expr\Variable && is_string($receiver->name)) {
            $type = self::variableType($receiver->name, $caller, $callerClass, $uses, $namespace);
            if ($type === null) {
                return null;
            }

            return ['class' => $type];
        }

        // new X / app(X::class) / resolve(X::class) inline.
        if ($receiver instanceof Node\Expr\New_ && $receiver->class instanceof Node\Name) {
            return ['class' => self::resolveName($receiver->class->toString(), $uses, $namespace)];
        }
        if (
            $receiver instanceof Node\Expr\FuncCall
            && $receiver->name instanceof Node\Name
            && in_array(strtolower($receiver->name->toString()), ['app', 'resolve'], true)
        ) {
            $arg = $receiver->args[0] ?? null;
            if (
                $arg instanceof Node\Arg
                && $arg->value instanceof Node\Expr\ClassConstFetch
                && $arg->value->class instanceof Node\Name
            ) {
                return ['class' => self::resolveName($arg->value->class->toString(), $uses, $namespace)];
            }
        }

        return null;
    }

    /**
     * @return array{class: string}|null
     */
    public static function classOf(Node\Stmt\Class_ $class, ?string $namespace): ?array
    {
        if ($class->name === null) {
            return null;
        }
        $short = $class->name->toString();

        return ['class' => $namespace !== null ? $namespace . '\\' . $short : $short];
    }

    /**
     * @param array<string, string> $uses
     */
    private static function propertyType(
        string $prop,
        Node\Stmt\Class_ $class,
        array $uses,
        ?string $namespace
    ): ?string {
        // Promoted constructor params and typed declarations.
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\ClassMethod && strtolower($stmt->name->toString()) === '__construct') {
                foreach ($stmt->params as $param) {
                    if (
                        $param instanceof Node\Param
                        && $param->var instanceof Node\Expr\Variable
                        && $param->var->name === $prop
                        && $param->type instanceof Node\Name
                        && !self::isBuiltin($param->type->toString())
                    ) {
                        // Promoted (flags set) or plain param feeding
                        // `$this->x = $param` below — either way the type
                        // is proven only if the assignment exists for
                        // plain params.
                        if (self::isPromoted($param) || self::assignedInConstructor($prop, $param, $stmt)) {
                            return self::resolveName($param->type->toString(), $uses, $namespace);
                        }
                    }
                }
            }
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $item) {
                    if (
                        $item instanceof Node\Stmt\PropertyProperty
                        && $item->name->toString() === $prop
                        && $stmt->type instanceof Node\Name
                        && !self::isBuiltin($stmt->type->toString())
                    ) {
                        return self::resolveName($stmt->type->toString(), $uses, $namespace);
                    }
                }
            }
        }

        return null;
    }

    private static function isPromoted(Node\Param $param): bool
    {
        return ($param->flags & Node\Stmt\Class_::MODIFIER_PUBLIC) !== 0
            || ($param->flags & Node\Stmt\Class_::MODIFIER_PROTECTED) !== 0
            || ($param->flags & Node\Stmt\Class_::MODIFIER_PRIVATE) !== 0;
    }

    private static function assignedInConstructor(
        string $prop,
        Node\Param $param,
        Node\Stmt\ClassMethod $ctor
    ): bool {
        if (!$param->var instanceof Node\Expr\Variable || !is_string($param->var->name)) {
            return false;
        }
        if ($ctor->stmts === null) {
            return false;
        }
        $finder = new NodeFinder();
        $found = $finder->find($ctor->stmts, static function (Node $node) use ($prop, $param): bool {
            return $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\PropertyFetch
                && $node->var->name instanceof Node\Identifier
                && $node->var->name->toString() === $prop
                && $node->var->var instanceof Node\Expr\Variable
                && $node->var->var->name === 'this'
                && $node->expr instanceof Node\Expr\Variable
                && $node->expr->name === $param->var->name;
        });

        return $found !== [];
    }

    /**
     * @param array<string, string> $uses
     */
    private static function variableType(
        string $name,
        Node\Stmt\ClassMethod $caller,
        Node\Stmt\Class_ $callerClass,
        array $uses,
        ?string $namespace
    ): ?string {
        if ($caller->stmts === null) {
            return null;
        }
        $finder = new NodeFinder();
        $assigns = [];
        foreach (
            $finder->find($caller->stmts, static function (Node $node) use ($name): bool {
                return $node instanceof Node\Expr\Assign
                    && $node->var instanceof Node\Expr\Variable
                    && $node->var->name === $name;
            }) as $assign
        ) {
            if ($assign instanceof Node\Expr\Assign) {
                $assigns[] = $assign;
            }
        }
        if (count($assigns) !== 1) {
            return null;
        }
        $rhs = $assigns[0]->expr;
        if ($rhs instanceof Node\Expr\New_ && $rhs->class instanceof Node\Name) {
            return self::resolveName($rhs->class->toString(), $uses, $namespace);
        }
        if (
            $rhs instanceof Node\Expr\FuncCall
            && $rhs->name instanceof Node\Name
            && in_array(strtolower($rhs->name->toString()), ['app', 'resolve'], true)
        ) {
            $arg = $rhs->args[0] ?? null;
            if (
                $arg instanceof Node\Arg
                && $arg->value instanceof Node\Expr\ClassConstFetch
                && $arg->value->class instanceof Node\Name
            ) {
                return self::resolveName($arg->value->class->toString(), $uses, $namespace);
            }
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
