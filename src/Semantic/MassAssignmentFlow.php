<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Analysis\FlowTrace;
use Rampart\QualityChecker\Analysis\ScopeResolver;

/**
 * Input-to-Eloquent flow classification (v0.4.1+, shadow mode).
 *
 * Classifies the data argument of a mass-assignment sink
 * (`create`/`fill`/`update`/`forceFill`/`forceCreate`/...) by provenance:
 * raw request data, validated data, bounded field-sets (`only()`),
 * internal literals, or unknown. Variable propagation is flow-sensitive
 * (one straight-line assignment preceding the use; same-scope filtered),
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
     * @param array<string, string> $uses
     */
    public static function classify(
        Node\Expr $arg,
        string $sinkMethod,
        Node\Stmt\ClassMethod $method,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine,
        ?MethodSummaryIndex $summaries = null,
        ?Node\Stmt\Class_ $callerClass = null,
        array $uses = [],
        ?string $namespace = null
    ): MassFlow {
        $forceBypass = in_array(strtolower($sinkMethod), ['forcefill', 'forcecreate'], true);
        $sinkLabel = $sinkMethod . '()';
        $flow = self::resolveSource($arg, $method, $fileNodes, $funcId, $file, $useLine, 0, [], $summaries, $callerClass, $uses, $namespace, false);
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
     * @param array<string, string> $uses
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
        array $visited,
        ?MethodSummaryIndex $summaries = null,
        ?Node\Stmt\Class_ $callerClass = null,
        array $uses = [],
        ?string $namespace = null,
        bool $inSummary = false
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
                $base = self::resolveSource($expr->var, $method, $fileNodes, $funcId, $file, $useLine, $depth + 1, $visited, $summaries, $callerClass, $uses, $namespace, $inSummary);
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
            // Bounded interprocedural call (opt-in, shadow): one call
            // boundary via a proven receiver + cached method summary.
            // Nested applications stay unresolved (depth 1).
            if (!$inSummary && $summaries !== null && $callerClass !== null) {
                $applied = self::applySummary(
                    $expr,
                    $method,
                    $callerClass,
                    $fileNodes,
                    $funcId,
                    $file,
                    $useLine,
                    $depth,
                    $summaries,
                    $uses,
                    $namespace
                );
                if ($applied !== null) {
                    return $applied;
                }

                return self::unresolvedFlow($expr, 'dynamic-receiver');
            }
        }

        // Single-assignment variables via flow-sensitive discipline.
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return self::resolveVariable($expr, $method, $fileNodes, $funcId, $file, $useLine, $depth, $visited, $summaries, $callerClass, $uses, $namespace, $inSummary);
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
     * @param array<string, string> $uses
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}|null
     */
    private static function resolveVariable(
        Node\Expr\Variable $use,
        Node\Stmt\ClassMethod $method,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine,
        int $depth,
        array $visited,
        ?MethodSummaryIndex $summaries = null,
        ?Node\Stmt\Class_ $callerClass = null,
        array $uses = [],
        ?string $namespace = null,
        bool $inSummary = false
    ): ?array {
        if (!is_string($use->name)) {
            return null;
        }
        $name = $use->name;
        // Flow-sensitive single assignment: exactly one straight-line
        // (direct method-body child) assignment preceding the use; any
        // other preceding same-scope assignment (conditional, loop)
        // poisons the proof. Later reassignments cannot affect the use.
        // Ordering uses file positions so same-line statements resolve.
        $usePos = (int) $use->getAttribute('startFilePos', -1);
        $direct = null;
        $finder = new CountingNodeFinder();
        $assigns = $finder->find(
            $method->stmts ?? [],
            static function (Node $node) use ($name): bool {
                return $node instanceof Node\Expr\Assign
                    && $node->var instanceof Node\Expr\Variable
                    && $node->var->name === $name;
            }
        );
        foreach ($assigns as $assign) {
            if (!$assign instanceof Node\Expr\Assign) {
                continue;
            }
            if (!self::strictlyBefore($assign, $useLine, $usePos)) {
                continue;
            }
            if (!self::isDirectChild($assign, $method)) {
                return null;
            }
            if ($direct !== null) {
                return null;
            }
            $direct = $assign;
        }
        if ($direct === null) {
            return null;
        }
        // Same-scope filter: file-level assigns must not leak in.
        if ((new ScopeResolver())->funcId($direct, $fileNodes) !== $funcId) {
            return null;
        }
        if (isset($visited[spl_object_id($direct)])) {
            return null;
        }
        $visited[spl_object_id($direct)] = true;
        $inner = self::resolveSource($direct->expr, $method, $fileNodes, $funcId, $file, $useLine, $depth + 1, $visited, $summaries, $callerClass, $uses, $namespace, $inSummary);
        if ($inner === null) {
            return null;
        }
        $inner['trace'][] = [
            'kind' => 'propagation',
            'detail' => '$' . $name . ' = ' . self::describe($direct->expr),
            'line' => $direct->getStartLine(),
        ];

        return $inner;
    }

    /**
     * Strict source order: earlier line wins; same line falls back to
     * file positions (absent positions mean unorderable → false).
     */
    private static function strictlyBefore(Node\Expr\Assign $assign, int $useLine, int $usePos): bool
    {
        if ($assign->getStartLine() < $useLine) {
            return true;
        }
        if ($assign->getStartLine() !== $useLine || $usePos < 0) {
            return false;
        }
        $assignPos = (int) $assign->getAttribute('startFilePos', -1);

        return $assignPos >= 0 && $assignPos < $usePos;
    }

    private static function isDirectChild(Node\Expr\Assign $assign, Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null) {
            return false;
        }
        $id = spl_object_id($assign);
        foreach ($method->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Expression && spl_object_id($stmt->expr) === $id) {
                return true;
            }
        }

        return false;
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
     * One interprocedural step: resolve the receiver, fetch the cached
     * summary, and apply the call-site arguments. Returns null when
     * anything is unproven (caller falls back to unknown).
     *
     * @param list<Node> $fileNodes
     * @param array<string, string> $uses
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}|null
     */
    private static function applySummary(
        Node\Expr\MethodCall $expr,
        Node\Stmt\ClassMethod $method,
        Node\Stmt\Class_ $callerClass,
        array $fileNodes,
        int $funcId,
        string $file,
        int $useLine,
        int $depth,
        MethodSummaryIndex $summaries,
        array $uses,
        ?string $namespace
    ): ?array {
        if (!$expr->name instanceof Node\Identifier) {
            return null;
        }
        $resolved = ReceiverResolver::resolve($expr->var, $method, $callerClass, $uses, $namespace);
        if ($resolved === null) {
            return null;
        }
        $methodName = $expr->name->toString();
        $summary = $summaries->summary($resolved['class'], $methodName);
        if ($summary->kind === MethodSummary::UNKNOWN) {
            return self::unresolvedFlow($expr, $summary->unresolvedReason ?? 'unsupported-expression');
        }
        // Visibility: protected members are only reachable through
        // $this; private members only through $this in the declaring
        // class itself. Anything else is not the resolved method.
        $isThis = $expr->var instanceof Node\Expr\Variable && $expr->var->name === 'this';
        if ($summary->visibility === 'protected' && !$isThis) {
            return self::unresolvedFlow($expr, 'visibility-incompatible');
        }
        if ($summary->visibility === 'private') {
            $callerFqn = $callerClass->name !== null
                ? ($namespace !== null ? $namespace . '\\' . $callerClass->name->toString() : $callerClass->name->toString())
                : null;
            if (
                !$isThis
                || $callerFqn === null
                || $summary->declaringClass === null
                || strtolower(ltrim($summary->declaringClass, '\\')) !== strtolower(ltrim($callerFqn, '\\'))
            ) {
                return self::unresolvedFlow($expr, 'visibility-incompatible');
            }
        }
        if ($summary->kind === MethodSummary::INTERNAL) {
            $trace = (new FlowTrace())->source('internal (' . $summary->evidence . ')', $expr->getStartLine())->toMetadata();

            return [
                'status' => MassFlow::INTERNAL,
                'fields' => null,
                'excluded' => null,
                'source' => 'internal via ' . $resolved['class'] . '::' . $methodName . '()',
                'trace' => $trace,
            ];
        }
        // PARAM(i, op): map the actual argument, then decide at the
        // call-site. Nested summaries stay unresolved (depth 1).
        $actual = self::mapArgument($expr, $summary);
        if ($actual === null) {
            return self::unresolvedFlow($expr, 'unsupported-expression');
        }
        $traceHead = [[
            'kind' => 'propagation',
            'detail' => $resolved['class'] . '::' . $methodName . '() => ' . $summary->evidence,
            'line' => $expr->getStartLine(),
        ]];
        if ($summary->operation === MethodSummary::OP_PASSTHROUGH) {
            $inner = self::resolveSource($actual, $method, $fileNodes, $funcId, $file, $useLine, $depth + 1, [], null, $callerClass, $uses, $namespace, true);
            if ($inner === null) {
                return null;
            }
            $inner['trace'] = [...$inner['trace'], ...$traceHead];

            return $inner;
        }
        if (!self::isRequestObject($actual, $method)) {
            return null;
        }
        $source = self::describe($actual) . ' via ' . $resolved['class'] . '::' . $methodName . '()';
        $trace = [...$traceHead];
        switch ($summary->operation) {
            case MethodSummary::OP_ALL:
            case MethodSummary::OP_INPUT:
                return ['status' => MassFlow::RAW, 'fields' => null, 'excluded' => null, 'source' => $source, 'trace' => $trace];
            case MethodSummary::OP_ONLY:
                if ($summary->fields === null) {
                    return null;
                }

                return ['status' => MassFlow::BOUNDED, 'fields' => $summary->fields, 'excluded' => null, 'source' => $source, 'trace' => $trace];
            case MethodSummary::OP_EXCEPT:
                return ['status' => MassFlow::RAW, 'fields' => null, 'excluded' => $summary->fields, 'source' => $source, 'trace' => $trace];
            case MethodSummary::OP_VALIDATED:
            case MethodSummary::OP_SAFE:
                return ['status' => MassFlow::VALIDATED, 'fields' => null, 'excluded' => null, 'source' => $source, 'trace' => $trace];
            default:
                return null;
        }
    }

    /**
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, source: string, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    private static function unresolvedFlow(Node\Expr $expr, string $reason): array
    {
        $trace = (new FlowTrace())->source(self::describe($expr), $expr->getStartLine())->toMetadata();
        $trace[] = ['kind' => 'unresolved', 'detail' => $reason, 'line' => $expr->getStartLine()];

        return [
            'status' => MassFlow::UNKNOWN,
            'fields' => null,
            'excluded' => null,
            'source' => self::describe($expr),
            'trace' => $trace,
        ];
    }

    /**
     * Actual argument expression for summary param $summary->paramIndex,
     * positional or named. Null when the argument is missing.
     */
    private static function mapArgument(
        Node\Expr\MethodCall $expr,
        MethodSummary $summary
    ): ?Node\Expr {
        if ($summary->paramIndex === null) {
            return null;
        }
        $paramName = $summary->params[$summary->paramIndex] ?? null;
        foreach ($expr->args as $arg) {
            if ($arg instanceof Node\Arg && $arg->name instanceof Node\Identifier && $arg->name->toString() === $paramName) {
                return $arg->value;
            }
        }
        $positional = array_values(array_filter($expr->args, static fn ($a): bool => $a instanceof Node\Arg && $a->name === null));
        $match = $positional[$summary->paramIndex] ?? null;

        return $match instanceof Node\Arg ? $match->value : null;
    }

    /**
     * Is this expression the request object (not request data)? Bounded:
     * `$request`, `$this->request`, `request()`, or a Request-typed
     * parameter of the enclosing method.
     */
    private static function isRequestObject(Node\Expr $expr, Node\Stmt\ClassMethod $method): bool
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            if ($expr->name === 'request') {
                return true;
            }
            foreach ($method->params as $param) {
                if (
                    $param instanceof Node\Param
                    && $param->var instanceof Node\Expr\Variable
                    && $param->var->name === $expr->name
                    && $param->type instanceof Node\Name
                    && str_contains(strtolower($param->type->toString()), 'request')
                ) {
                    return true;
                }
            }

            return false;
        }
        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && $expr->name->toString() === 'request'
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
        ) {
            return true;
        }
        if ($expr instanceof Node\Expr\FuncCall) {
            return $expr->name instanceof Node\Name
                && strtolower($expr->name->toString()) === 'request';
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
