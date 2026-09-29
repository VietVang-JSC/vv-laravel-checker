<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use Rampart\QualityChecker\Profiling\Profiler;

/**
 * Tier 2 middleware resolution: inspect a middleware `handle()` for
 * bounded authorization patterns. Returns evidence — never a bare
 * boolean — or null when the implementation is not understood.
 *
 * A trigger (gate call or role-literal comparison) only counts when it
 * structurally gates `$next()`: it must sit in the condition of a
 * top-level `if` (or an `abort_if`/`abort_unless`) whose two sides split
 * into exactly one pass side (`return $next(...)`) and one failing side
 * (deny-shape or redirect). Triggers nested inside unrelated conditions
 * — e.g. a role check conjoined with a maintenance-mode flag — do NOT
 * count: they gate a branch, not the request.
 *
 * Recognized (deliberately narrow):
 * - `Gate::allows()/authorize()`, `Gate::forUser(...)->allows(...)`,
 *   `$user->can()` / `$request->user()->can()` with a deny-shape
 *   (`abort*()`, `throw`, HTTP 403 literal) on the failing path. A bare
 *   `Gate::authorize()` throws on denial, so it is self-enforcing.
 * - Role-literal guards: `->role` / `->is_admin` / `->isAdmin` /
 *   `->user_role` compared against a literal, passing to `$next()` and
 *   failing to a deny-shape (high confidence) or a redirect (medium —
 *   redirects prove a gate but are weaker evidence than a 403).
 *
 * Explicitly NOT recognized (stays review):
 * - Ownership / object-level checks (`$user->id != $link->user_id`) —
 *   data-flow territory, fixture for a later phase.
 * - Redirect-only fallbacks without a role/ability condition.
 * - Truthy flag checks without a literal (`if ($user->blocked)`).
 * - Inverted role checks (`if ($role == 'x') abort; else $next`) — they
 *   deny one value instead of authorizing the action.
 */
final class MiddlewareInspector
{
    private const ROLE_PROPS = ['role', 'is_admin', 'isAdmin', 'user_role', 'userRole'];

    private const GATE_METHODS = ['allows', 'authorize', 'check', 'any'];

    public function inspect(string $file, string $class, string $alias, ?string $routeAbility = null): ?MiddlewareEvidence
    {
        $handle = $this->handleMethod($file);
        if ($handle === null || $handle->stmts === null) {
            return null;
        }
        if (!$this->passesNext(new NodeFinder(), $handle)) {
            return null;
        }

        foreach ($handle->stmts as $i => $stmt) {
            $evidence = $this->guardEvidence(
                $file,
                $handle->stmts,
                (int) $i,
                $class,
                $alias,
                $routeAbility
            );
            if ($evidence instanceof MiddlewareEvidence) {
                return $evidence;
            }
        }

        return null;
    }

    /**
     * One top-level statement shaped like a request gate: an `if` whose
     * condition carries exactly one trigger (gate call or role-literal
     * comparison, optionally &&-ed with auth-context checks) and whose
     * branches split pass vs fail — or an abort_if/abort_unless trigger,
     * or a bare self-enforcing Gate::authorize().
     * @param list<Node\Stmt> $stmts sibling statements (the failing path
     *   of an elseless `if` is everything after it)
     */
    private function guardEvidence(
        string $file,
        array $stmts,
        int $index,
        string $class,
        string $alias,
        ?string $routeAbility
    ): ?MiddlewareEvidence {
        $stmt = $stmts[$index];
        if ($stmt instanceof Node\Stmt\If_) {
            return $this->ifEvidence(
                $file,
                $stmt,
                array_slice($stmts, $index + 1),
                $class,
                $alias,
                $routeAbility
            );
        }
        if ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Node\Expr\FuncCall) {
            $call = $stmt->expr;
            if (
                $call->name instanceof Node\Name
                && in_array(strtolower($call->name->toString()), ['abort_if', 'abort_unless'], true)
            ) {
                return $this->abortEvidence($file, $call, $class, $alias, $routeAbility);
            }
        }
        if ($this->isSelfEnforcingAuthorize($stmt)) {
            return new MiddlewareEvidence(
                'middleware',
                $alias,
                $class,
                'handle',
                MiddlewareEvidence::MECHANISM_GATE,
                $routeAbility ?? $this->callAbility($stmt),
                $this->sourceRef($file, $stmt),
                'high'
            );
        }

        return null;
    }

    /**
     * @param list<Node\Stmt> $after statements following the `if`
     *   (the failing path when there is no else)
     */
    private function ifEvidence(
        string $file,
        Node\Stmt\If_ $if,
        array $after,
        string $class,
        string $alias,
        ?string $routeAbility
    ): ?MiddlewareEvidence {
        $operands = $this->andOperands($if->cond);
        if ($operands === null) {
            return null;
        }
        $trigger = null;
        foreach ($operands as $operand) {
            $kind = $this->operandTrigger($operand);
            if ($kind === null) {
                // An unrelated sibling (feature flag, env check, ...) —
                // the trigger gates a branch, not the request.
                if (!$this->isAuthContext($operand)) {
                    return null;
                }
                continue;
            }
            if ($trigger !== null) {
                // Two triggers: out of bounded scope, stay silent.
                return null;
            }
            $trigger = $kind;
        }
        if ($trigger === null) {
            return null;
        }

        // Branch discipline with polarity: positive triggers (allows,
        // can, ==) pass on true; negative triggers (denies, !=) deny on
        // true. Exactly one side may reach $next; without an else the
        // failing path is everything after the `if`.
        // elseif chains are out of bounded scope.
        if ($if->elseifs !== []) {
            return null;
        }
        $thenNext = $this->reachesNext($if->stmts);
        if ($if->else !== null) {
            $elseNext = $this->reachesNext($if->else->stmts);
            if ($thenNext === $elseNext) {
                return null;
            }
            $failStmts = $thenNext ? $if->else->stmts : $if->stmts;
        } else {
            // No else: the `if` must pass to $next and the fallthrough
            // must block (positive trigger), or deny in-branch with $next
            // after (negative trigger).
            $passOnTrue = in_array($trigger['polarity'], ['allows', 'equal'], true);
            if ($passOnTrue) {
                if (!$thenNext) {
                    return null;
                }
                $failStmts = $after;
            } else {
                if ($thenNext || !$this->reachesNext($after)) {
                    return null;
                }
                $failStmts = $if->stmts;
            }
        }
        $passOnTrue = in_array($trigger['polarity'], ['allows', 'equal'], true);
        if ($passOnTrue !== $thenNext) {
            // Inverted shape (e.g. `if ($role == 'x') abort; else $next`)
            // denies one value instead of authorizing the action.
            return null;
        }
        $strength = $this->blockStrength($failStmts);
        if ($strength === null) {
            return null;
        }

        return new MiddlewareEvidence(
            'middleware',
            $alias,
            $class,
            'handle',
            $trigger['mechanism'],
            $routeAbility ?? $trigger['ability'],
            $this->sourceRef($file, $if),
            $strength === 'redirect' ? 'medium' : 'high'
        );
    }

    /**
     * abort_if(cond, code) / abort_unless(cond, code) with a single
     * trigger condition (auth-context &&-siblings tolerated).
     */
    private function abortEvidence(
        string $file,
        Node\Expr\FuncCall $call,
        string $class,
        string $alias,
        ?string $routeAbility
    ): ?MiddlewareEvidence {
        $condArg = $call->args[0] ?? null;
        if (!$condArg instanceof Node\Arg) {
            return null;
        }
        $operands = $this->andOperands($condArg->value);
        if ($operands === null) {
            return null;
        }
        $trigger = null;
        foreach ($operands as $operand) {
            $kind = $this->operandTrigger($operand);
            if ($kind === null) {
                if (!$this->isAuthContext($operand)) {
                    return null;
                }
                continue;
            }
            if ($trigger !== null) {
                return null;
            }
            $trigger = $kind;
        }
        if ($trigger === null) {
            return null;
        }
        // abort_if denies on true, abort_unless denies on false: the
        // trigger polarity must oppose the abort polarity, otherwise the
        // trigger passes exactly when abort fires (not a gate).
        $name = $call->name instanceof Node\Name ? strtolower($call->name->toString()) : '';
        $deniesOnTrue = $name === 'abort_if';
        $passOnTrue = in_array($trigger['polarity'], ['allows', 'equal'], true);
        if ($passOnTrue === $deniesOnTrue) {
            return null;
        }
        $codeArg = $call->args[1] ?? null;
        $code = $codeArg instanceof Node\Arg && $codeArg->value instanceof Node\Scalar\Int_
            ? $codeArg->value->value
            : null;

        return new MiddlewareEvidence(
            'middleware',
            $alias,
            $class,
            'handle',
            $trigger['mechanism'],
            $routeAbility ?? $trigger['ability'],
            $this->sourceRef($file, $call),
            $code === 403 ? 'high' : 'medium'
        );
    }

    private function handleMethod(string $file): ?Node\Stmt\ClassMethod
    {
        $code = is_file($file) ? file_get_contents($file) : false;
        if (!is_string($code) || $code === '') {
            return null;
        }
        try {
            $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($code);
            Profiler::countParse($file);
        } catch (\Throwable $e) {
            return null;
        }
        if ($ast === null) {
            return null;
        }
        $finder = new NodeFinder();
        $methods = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod;
        });
        foreach ($methods as $method) {
            if (
                $method instanceof Node\Stmt\ClassMethod
                && strtolower($method->name->toString()) === 'handle'
            ) {
                return $method;
            }
        }

        return null;
    }

    /**
     * The middleware lets requests through somewhere ($next(...)).
     */
    private function passesNext(NodeFinder $finder, Node\Stmt\ClassMethod $handle): bool
    {
        $calls = $finder->find($handle->stmts ?? [], static function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Expr\Variable
                && $node->name->name === 'next';
        });

        return $calls !== [];
    }

    /**
     * Split a condition into top-level && operands. || conditions are
     * out of bounded scope (null) — either side alone does not gate.
     *
     * @return list<Node\Expr>|null
     */
    private function andOperands(Node\Expr $cond): ?array
    {
        if ($cond instanceof Node\Expr\BinaryOp\BooleanAnd) {
            $left = $this->andOperands($cond->left);
            $right = $this->andOperands($cond->right);
            if ($left === null || $right === null) {
                return null;
            }

            return array_merge($left, $right);
        }
        if ($cond instanceof Node\Expr\BinaryOp\BooleanOr) {
            return null;
        }

        return [$cond];
    }

    /**
     * Classify one condition operand as a gate trigger with polarity,
     * or null when it is not a trigger at all.
     *
     * @return array{mechanism: string, polarity: string, ability: string|null}|null
     */
    private function operandTrigger(Node\Expr $operand): ?array
    {
        if (
            $operand instanceof Node\Expr\StaticCall
            && $operand->class instanceof Node\Name
            && $this->shortClass($operand->class->toString()) === 'Gate'
            && $operand->name instanceof Node\Identifier
        ) {
            $method = strtolower($operand->name->toString());
            if (in_array($method, self::GATE_METHODS, true)) {
                return [
                    'mechanism' => MiddlewareEvidence::MECHANISM_GATE,
                    'polarity' => 'allows',
                    'ability' => $this->callAbility($operand),
                ];
            }
            if ($method === 'denies') {
                return [
                    'mechanism' => MiddlewareEvidence::MECHANISM_GATE,
                    'polarity' => 'denies',
                    'ability' => $this->callAbility($operand),
                ];
            }

            return null;
        }
        if (
            $operand instanceof Node\Expr\MethodCall
            && $operand->name instanceof Node\Identifier
            && in_array(strtolower($operand->name->toString()), ['can', 'allows', 'authorize'], true)
            && $this->isUserContext($operand->var)
        ) {
            return [
                'mechanism' => MiddlewareEvidence::MECHANISM_GATE,
                'polarity' => 'allows',
                'ability' => $this->callAbility($operand),
            ];
        }
        if (
            $operand instanceof Node\Expr\BinaryOp\Equal
            || $operand instanceof Node\Expr\BinaryOp\Identical
            || $operand instanceof Node\Expr\BinaryOp\NotEqual
            || $operand instanceof Node\Expr\BinaryOp\NotIdentical
        ) {
            $positive = $operand instanceof Node\Expr\BinaryOp\Equal
                || $operand instanceof Node\Expr\BinaryOp\Identical;
            foreach ([$operand->left, $operand->right] as $i => $side) {
                $other = $i === 0 ? $operand->right : $operand->left;
                if (
                    $side instanceof Node\Expr\PropertyFetch
                    && $other instanceof Node\Scalar\String_
                    && $side->name instanceof Node\Identifier
                    && in_array($side->name->toString(), self::ROLE_PROPS, true)
                ) {
                    return [
                        'mechanism' => MiddlewareEvidence::MECHANISM_ROLE,
                        'polarity' => $positive ? 'equal' : 'notequal',
                        'ability' => $other->value,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Bare identity checks tolerated as &&-siblings of a trigger
     * (`Auth::user() && $user->role == 'admin'`): they narrow the gate
     * without changing what it proves.
     */
    private function isAuthContext(Node\Expr $operand): bool
    {
        if ($operand instanceof Node\Expr\FuncCall) {
            return $operand->name instanceof Node\Name
                && in_array(strtolower($operand->name->toString()), ['auth', 'user'], true);
        }

        return $this->isUserContext($operand);
    }

    private function isUserContext(Node\Expr $var): bool
    {
        if ($var instanceof Node\Expr\Variable) {
            return in_array($var->name, ['user', 'request'], true);
        }
        if ($var instanceof Node\Expr\StaticCall) {
            return $var->class instanceof Node\Name
                && in_array($this->shortClass($var->class->toString()), ['Auth', 'Request'], true);
        }
        if ($var instanceof Node\Expr\FuncCall) {
            return $var->name instanceof Node\Name
                && in_array(strtolower($var->name->toString()), ['auth', 'user'], true);
        }
        if ($var instanceof Node\Expr\MethodCall || $var instanceof Node\Expr\PropertyFetch) {
            return $var->var instanceof Node\Expr && $this->isUserContext($var->var);
        }

        return false;
    }

    private function isSelfEnforcingAuthorize(Node\Stmt $stmt): bool
    {
        $found = (new NodeFinder())->find($stmt, function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall
                && $node->class instanceof Node\Name
                && $this->shortClass($node->class->toString()) === 'Gate'
                && $node->name instanceof Node\Identifier
                && strtolower($node->name->toString()) === 'authorize';
        });

        return $found !== [];
    }

    private function callAbility(Node\Stmt|Node\Expr $node): ?string
    {
        if (
            ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall)
            && $node->name instanceof Node\Identifier
        ) {
            $arg = $node->args[0] ?? null;
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                return $arg->value->value;
            }

            return null;
        }
        $found = (new NodeFinder())->find($node, static function (Node $inner): bool {
            return ($inner instanceof Node\Expr\StaticCall || $inner instanceof Node\Expr\MethodCall)
                && $inner->name instanceof Node\Identifier;
        });
        foreach ($found as $candidate) {
            if (
                $candidate instanceof Node\Expr\StaticCall
                || $candidate instanceof Node\Expr\MethodCall
            ) {
                $arg = $candidate->args[0] ?? null;
                if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
                    return $arg->value->value;
                }

                return null;
            }
        }

        return null;
    }

    /**
     * @param list<Node\Stmt> $stmts
     */
    private function reachesNext(array $stmts): bool
    {
        $calls = (new NodeFinder())->find($stmts, static function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Expr\Variable
                && $node->name->name === 'next';
        });

        return $calls !== [];
    }

    /**
     * Failing-side strength: 'deny' (abort/throw/403), 'redirect'
     * (weaker), or null (no visible failing path).
     *
     * @param list<Node\Stmt> $stmts
     */
    private function blockStrength(array $stmts): ?string
    {
        $finder = new NodeFinder();
        $deny = $finder->find($stmts, static function (Node $node): bool {
            if ($node instanceof Node\Expr\Throw_) {
                return true;
            }
            if (
                $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Name
                && in_array(strtolower($node->name->toString()), ['abort', 'abort_if', 'abort_unless'], true)
            ) {
                return true;
            }
            if (
                $node instanceof Node\Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && in_array(strtolower($node->name->toString()), ['abort', 'abortif', 'abortunless'], true)
            ) {
                return true;
            }
            if ($node instanceof Node\Scalar\Int_ && $node->value === 403) {
                return true;
            }

            return false;
        });
        if ($deny !== []) {
            return 'deny';
        }

        // Redirects prove a gate but not an authorization denial.
        // `Redirect::` facades are out of scope for this bounded pass.
        $redirect = $finder->find($stmts, static function (Node $node): bool {
            if (
                $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Name
                && in_array(strtolower($node->name->toString()), ['redirect', 'back'], true)
            ) {
                return true;
            }
            if (
                $node instanceof Node\Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && in_array(strtolower($node->name->toString()), ['redirect', 'redirectto', 'redirectroute'], true)
            ) {
                return true;
            }

            return false;
        });

        return $redirect !== [] ? 'redirect' : null;
    }

    private function sourceRef(string $file, Node $node): string
    {
        return pathinfo($file, PATHINFO_BASENAME) . ':' . $node->getStartLine();
    }

    private function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
