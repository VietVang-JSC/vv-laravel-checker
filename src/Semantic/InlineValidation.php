<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;

/**
 * Inline validation recognition for a controller method body:
 * `$request->validate([...])`, `Validator::make(...)`, and
 * `validated()`/`safe()` uses. Pure and unit-testable — the seam the
 * validation rule consumes.
 *
 * `$request->validate()` with a literal array yields known fields;
 * anything else yields presence with unknown fields. `validated()` /
 * `safe()` mark validated-data *use* (the bridge future mass-assignment
 * work needs), not field definitions.
 */
final class InlineValidation
{
    /**
     * @return list<ValidationEvidence> strongest first
     */
    public static function recognize(Node\Stmt\ClassMethod $method): array
    {
        if ($method->stmts === null) {
            return [];
        }
        $finder = new CountingNodeFinder();
        $out = [];

        $validates = $finder->find($method->stmts, static function (Node $node): bool {
            return $node instanceof Node\Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && in_array(strtolower($node->name->toString()), ['validate', 'validatewithbag'], true);
        });
        foreach ($validates as $call) {
            if ($call instanceof Node\Expr\MethodCall) {
                $out[] = new ValidationEvidence(
                    ValidationEvidence::SOURCE_INLINE,
                    null,
                    true,
                    self::arrayFields($call->args[0] ?? null),
                    self::arrayFields($call->args[0] ?? null) !== null ? 'high' : 'medium'
                );
            }
        }

        $makes = $finder->find($method->stmts, static function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall
                && $node->class instanceof Node\Name
                && str_ends_with($node->class->toString(), 'Validator')
                && $node->name instanceof Node\Identifier
                && strtolower($node->name->toString()) === 'make';
        });
        foreach ($makes as $call) {
            if ($call instanceof Node\Expr\StaticCall) {
                $out[] = new ValidationEvidence(
                    ValidationEvidence::SOURCE_MAKE,
                    null,
                    true,
                    self::arrayFields($call->args[1] ?? null),
                    self::arrayFields($call->args[1] ?? null) !== null ? 'high' : 'medium'
                );
            }
        }

        $uses = $finder->find($method->stmts, static function (Node $node): bool {
            return $node instanceof Node\Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && in_array(strtolower($node->name->toString()), ['validated', 'safe'], true);
        });
        if ($uses !== []) {
            $out[] = new ValidationEvidence(
                ValidationEvidence::SOURCE_VALIDATED,
                null,
                true,
                null,
                'high'
            );
        }

        return $out;
    }

    /**
     * @param Node\Arg|Node\VariadicPlaceholder|null $arg
     * @return list<string>|null null = not a literal array
     */
    private static function arrayFields(?Node $arg): ?array
    {
        if (!$arg instanceof Node\Arg || !$arg->value instanceof Node\Expr\Array_) {
            return null;
        }
        $fields = [];
        foreach ($arg->value->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                return null;
            }
            $fields[] = $item->key->value;
        }

        return $fields;
    }
}
