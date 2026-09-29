<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Analysis\AssignmentMap;
use Rampart\QualityChecker\Analysis\FlowTrace;
use Rampart\QualityChecker\Analysis\ScopeResolver;

/**
 * Input-to-Eloquent flow classification (v0.4.1, shadow mode).
 *
 * Classifies the data argument of a mass-assignment sink
 * (`create`/`fill`/`update`/`forceFill`/`forceCreate`/...) by provenance:
 * raw request data, validated data, bounded field-sets (`only()`),
 * internal literals, or unknown. Variable propagation reuses the shared
 * engine (`AssignmentMap::visible` — same scope, straight-line, ordered),
 * so conditional mixes degrade to unknown instead of false-safe.
 *
 * Classification only — no verdicts. In particular `validated` never
 * implies mass-assignment safe; field-set reasoning against
 * `$fillable`/`$guarded` lands in v0.4.2.
 */
final class MassAssignmentFlow
{
    private const MAX_DEPTH = 4;

    /**
     * @param list<Node> $fileNodes
     */
    public static function classify(
        Node\Expr $arg,
        string $sinkMethod,
        Node\Stmt\ClassMethod $method,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine
    ): MassFlow {
        $forceBypass = in_array(strtolower($sinkMethod), ['forcefill', 'forcecreate'], true);
        $sinkLabel = $sinkMethod . '()';
        $flow = self::resolveSource($arg, $method, $fileNodes, $funcId, $file, $useLine, 0, []);
        if ($flow === null) {
            return new MassFlow(
                MassFlow::UNKNOWN,
                null,
                null,
                $forceBypass,
                self::describe($arg),
                $sinkLabel,
                (new FlowTrace())->sink($sinkLabel, $useLine)->toMetadata()
            );
        }
        $trace = [...$flow['trace'], ['kind' => 'sink', 'detail' => $sinkLabel, 'line' => $useLine]];

        return new MassFlow(
            $flow['status'],
            $flow['fields'],
            $flow['excluded'],
            $forceBypass,
            $flow['source'],
            $sinkLabel,
            $trace
        );
    }

    /**
     * @param list<Node> $fileNodes
     * @param array<int, true> $visited
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}|null
     */
    private static function resolveSource(
        Node\Expr $expr,
        Node\Stmt\ClassMethod $method,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine,
        int $depth,
        array $visited
    ): ?array {
        if ($depth > self::MAX_DEPTH) {
            return null;
        }

        // $request->all()/input()/only()/except()/validated()/safe() and
        // request()->... chains.
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $name = strtolower($expr->name->toString());
            if (in_array($name, ['all', 'input', 'only', 'except'], true) && self::isRequestReceiver($expr->var)) {
                return self::requestSource($expr, $name);
            }
            if (in_array($name, ['validated', 'safe', 'validate', 'validatewithbag'], true)) {
                return self::validatedSource($expr, $name);
            }
            // safe()->only([...]) / safe()->except([...]): validated base
            // with a field-set operation on top.
            if (in_array($name, ['only', 'except'], true)) {
                $base = self::resolveSource($expr->var, $method, $fileNodes, $funcId, $file, $useLine, $depth + 1, $visited);
                if ($base !== null && $base['status'] === MassFlow::VALIDATED) {
                    $fields = self::literalFields($expr);
                    $trace = [...$base['trace'], [
                        'kind' => 'propagation',
                        'detail' => self::describe($expr),
                        'line' => $expr->getStartLine(),
                    ]];
                    if ($name === 'only') {
                        return [
                            'status' => $fields !== null ? MassFlow::BOUNDED : MassFlow::UNKNOWN,
                            'fields' => $fields,
                            'excluded' => $base['excluded'],
                            'source' => $base['source'],
                            'trace' => $trace,
                        ];
                    }

                    return [
                        'status' => MassFlow::VALIDATED,
                        'fields' => null,
                        'excluded' => $fields,
                        'source' => $base['source'],
                        'trace' => $trace,
                    ];
                }
            }
        }

        // Single-assignment variables via the shared engine.
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return self::resolveVariable($expr->name, $method, $fileNodes, $funcId, $file, $useLine, $depth, $visited);
        }

        // Literal arrays are internal data, never request-tainted.
        if ($expr instanceof Node\Expr\Array_) {
            $trace = (new FlowTrace())->source('literal array', $expr->getStartLine())->toMetadata();

            return [
                'status' => MassFlow::INTERNAL,
                'fields' => null,
                'excluded' => null,
                'source' => 'literal array',
                'trace' => $trace,
            ];
        }

        return null;
    }

    /**
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    private static function requestSource(Node\Expr\MethodCall $expr, string $name): array
    {
        $label = self::describe($expr);
        $line = $expr->getStartLine();
        $trace = (new FlowTrace())->source($label, $line)->toMetadata();
        if ($name === 'only') {
            $fields = self::literalFields($expr);
            if ($fields !== null) {
                return [
                    'status' => MassFlow::BOUNDED,
                    'fields' => $fields,
                    'excluded' => null,
                    'source' => $label,
                    'trace' => $trace,
                ];
            }

            return [
                'status' => MassFlow::UNKNOWN,
                'fields' => null,
                'excluded' => null,
                'source' => $label,
                'trace' => $trace,
            ];
        }
        if ($name === 'except') {
            return [
                'status' => MassFlow::RAW,
                'fields' => null,
                'excluded' => self::literalFields($expr),
                'source' => $label,
                'trace' => $trace,
            ];
        }

        return [
            'status' => MassFlow::RAW,
            'fields' => null,
            'excluded' => null,
            'source' => $label,
            'trace' => $trace,
        ];
    }

    /**
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    private static function validatedSource(Node\Expr\MethodCall $expr, string $name): array
    {
        $label = self::describe($expr);
        $trace = (new FlowTrace())->source($label, $expr->getStartLine())->toMetadata();
        if (in_array($name, ['validate', 'validatewithbag'], true)) {
            return [
                'status' => MassFlow::VALIDATED,
                'fields' => self::literalFields($expr),
                'excluded' => null,
                'source' => $label,
                'trace' => $trace,
            ];
        }

        return [
            'status' => MassFlow::VALIDATED,
            'fields' => null,
            'excluded' => null,
            'source' => $label,
            'trace' => $trace,
        ];
    }

    /**
     * @param list<Node> $fileNodes
     * @param array<int, true> $visited
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}|null
     */
    private static function resolveVariable(
        string $name,
        Node\Stmt\ClassMethod $method,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine,
        int $depth,
        array $visited
    ): ?array {
        // Exactly one assignment to the name in the whole method: any
        // conditional/loop reassignment degrades to unknown (never
        // false-safe), even when the straight-line view sees only one.
        $allInMethod = (new NodeFinder())->find(
            $method->stmts ?? [],
            static function (Node $node) use ($name): bool {
                return $node instanceof Node\Expr\Assign
                    && $node->var instanceof Node\Expr\Variable
                    && $node->var->name === $name;
            }
        );
        if (count($allInMethod) !== 1) {
            return null;
        }
        // Shared-engine discipline with same-scope filtering: file-level
        // assigns must not leak into method scope.
        $scopes = new ScopeResolver();
        $assigns = [];
        foreach ((new AssignmentMap())->visible($fileNodes, $funcId, $useLine) as $assign) {
            if (
                $assign->var instanceof Node\Expr\Variable
                && $assign->var->name === $name
                && $scopes->funcId($assign, $fileNodes) === $funcId
            ) {
                $assigns[] = $assign;
            }
        }
        // Shared-engine discipline: exactly one straight-line,
        // same-scope, preceding assignment. Conditional mixes and
        // reassignments degrade to unknown (never false-safe).
        if (count($assigns) !== 1) {
            return null;
        }
        $assign = $assigns[0];
        if (isset($visited[spl_object_id($assign)])) {
            return null;
        }
        $visited[spl_object_id($assign)] = true;
        $inner = self::resolveSource($assign->expr, $method, $fileNodes, $funcId, $file, $useLine, $depth + 1, $visited);
        if ($inner === null) {
            return null;
        }
        $inner['trace'][] = [
            'kind' => 'propagation',
            'detail' => '$' . $name . ' = ' . self::describe($assign->expr),
            'line' => $assign->getStartLine(),
        ];

        return $inner;
    }

    private static function isRequestReceiver(Node\Expr $var): bool
    {
        if ($var instanceof Node\Expr\Variable) {
            return $var->name === 'request';
        }
        if (
            $var instanceof Node\Expr\PropertyFetch
            && $var->name instanceof Node\Identifier
            && $var->name->toString() === 'request'
            && $var->var instanceof Node\Expr\Variable
            && $var->var->name === 'this'
        ) {
            return true;
        }
        if ($var instanceof Node\Expr\FuncCall) {
            return $var->name instanceof Node\Name
                && strtolower($var->name->toString()) === 'request';
        }

        return false;
    }

    /**
     * @return list<string>|null literal field list, null when dynamic
     */
    private static function literalFields(Node\Expr\MethodCall $expr): ?array
    {
        $arg = $expr->args[0] ?? null;
        if (!$arg instanceof Node\Arg || !$arg->value instanceof Node\Expr\Array_) {
            return null;
        }
        $fields = [];
        foreach ($arg->value->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                // only(['a', 'b']) uses values, not keys.
                if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                    $fields[] = $item->value->value;
                    continue;
                }

                return null;
            }
            $fields[] = $item->key->value;
        }

        return $fields;
    }

    private static function describe(Node\Expr $expr): string
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return '$' . $expr->name;
        }
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            return self::describe($expr->var) . '->' . $expr->name->toString() . '()';
        }
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return $expr->name->toString() . '()';
        }
        if ($expr instanceof Node\Expr\Array_) {
            return 'literal array';
        }
        if ($expr instanceof Node\Expr\PropertyFetch) {
            return self::describe($expr->var) . '->...';
        }

        return strtolower((new \ReflectionClass($expr))->getShortName());
    }
}
