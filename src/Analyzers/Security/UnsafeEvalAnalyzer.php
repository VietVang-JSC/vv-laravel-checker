<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03 Injection - unsafe eval.
 *
 * Flags eval()/assert()/create_function()/call_user_func()/call_user_func_array()
 * with a non-literal first argument, unless
 * every dynamic leaf was validated by preg_match()/preg_match_all() in the
 * same function (e.g. a math expression allow-listed before eval). The filter
 * strength itself is not verified — this is a heuristic.
 */
final class UnsafeEvalAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'UNSAFE_EVAL';

    private const FUNCTIONS = ['eval', 'assert', 'create_function', 'call_user_func', 'call_user_func_array'];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return [];
        }

        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }

        $issues = [];
        $calls = $this->finder()->findInstanceOf($nodes, Node\Expr\FuncCall::class);
        $evals = $this->finder()->findInstanceOf($nodes, Node\Expr\Eval_::class);

        foreach ($calls as $call) {
            if (!$call->name instanceof Node\Name) {
                continue;
            }

            $name = strtolower($call->name->toString());
            if (!in_array($name, self::FUNCTIONS, true)) {
                continue;
            }

            if (count($call->args) === 0) {
                continue;
            }

            $firstArg = $call->args[0]->value;
            if ($this->isStaticValue($firstArg)) {
                continue;
            }
            // assert() with a provably-boolean argument (instanceof,
            // comparisons, empty()/isset(), is_*/has_* checks, boolean
            // operators) cannot carry code — there is nothing to evaluate.
            if ($name === 'assert' && $this->isBooleanExpression($firstArg)) {
                continue;
            }
            // call_user_func([$this, 'handle'], $userInput) passes user data
            // as an argument to a fixed method — the callable itself is not
            // attacker-controlled, so this is not code injection. Only the
            // callable position (first arg) matters.
            if (
                in_array($name, ['call_user_func', 'call_user_func_array'], true)
                && $this->isFixedCallable($firstArg)
            ) {
                continue;
            }
            if ($this->isValidatedExpression($firstArg, $call, $nodes)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('%s() is called with non-literal input; this can lead to arbitrary code execution.', $name),
                $file,
                $call->getStartLine(),
                Severity::Critical,
                ['function' => $name]
            );
        }

        foreach ($evals as $eval) {
            $expr = $eval->expr;
            if ($this->isStaticValue($expr)) {
                continue;
            }
            if ($this->isValidatedExpression($expr, $eval, $nodes)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                'eval() is called with non-literal input; this can lead to arbitrary code execution.',
                $file,
                $eval->getStartLine(),
                Severity::Critical,
                ['function' => 'eval']
            );
        }

        return $issues;
    }

    private function isStaticValue(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\LNumber || $expr instanceof Node\Scalar\DNumber) {
            return true;
        }

        if ($expr instanceof Node\Expr\ConstFetch) {
            return in_array(strtolower($expr->name->toString()), ['true', 'false', 'null'], true);
        }

        return false;
    }

    /**
     * Provably-boolean expressions: instanceof, comparisons, empty/isset,
     * boolean not/and/or, and predicate-style calls (is_xxx, has_xxx,
     * can_xxx). A variable or arbitrary call stays flaggable — it could
     * hold a string.
     */
    private function isBooleanExpression(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Instanceof_) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\BinaryOp\Identical
            || $expr instanceof Node\Expr\BinaryOp\NotIdentical
            || $expr instanceof Node\Expr\BinaryOp\Equal
            || $expr instanceof Node\Expr\BinaryOp\NotEqual
            || $expr instanceof Node\Expr\BinaryOp\Greater
            || $expr instanceof Node\Expr\BinaryOp\GreaterOrEqual
            || $expr instanceof Node\Expr\BinaryOp\Smaller
            || $expr instanceof Node\Expr\BinaryOp\SmallerOrEqual
            || $expr instanceof Node\Expr\BinaryOp\Spaceship
            || $expr instanceof Node\Expr\BinaryOp\BooleanAnd
            || $expr instanceof Node\Expr\BinaryOp\BooleanOr
            || $expr instanceof Node\Expr\BinaryOp\LogicalAnd
            || $expr instanceof Node\Expr\BinaryOp\LogicalOr
            || $expr instanceof Node\Expr\BooleanNot
            || $expr instanceof Node\Expr\Empty_
            || $expr instanceof Node\Expr\Isset_
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->toString());
            if ($fn === 'empty' || $fn === 'isset') {
                return true;
            }

            return (bool) preg_match('/^(is_|has_|can_)/', $fn);
        }

        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            return (bool) preg_match('/^(is|has|can)[A-Z_]/', $expr->name->toString());
        }

        return false;
    }

    /**
     * A callable that cannot be influenced by input: string literal,
     * constant, closure, an app()/resolve() lookup with all-literal
     * arguments (service-container bindings are deploy-time), or an array
     * of static parts such as [$this, 'handle'] or ['Class', 'method'].
     * A dynamic element (e.g. [$this, $method]) stays flaggable.
     */
    private function isFixedCallable(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Expr\ConstFetch
            || $expr instanceof Node\Expr\ClassConstFetch
            || $expr instanceof Node\Expr\Closure
            || $expr instanceof Node\Expr\ArrowFunction
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->toString());
            if (($fn === 'app' || $fn === 'resolve') && $expr->args !== []) {
                foreach ($expr->args as $arg) {
                    if (
                        !$arg instanceof Node\Arg
                        || !($arg->value instanceof Node\Scalar
                            || $arg->value instanceof Node\Expr\ConstFetch
                            || $arg->value instanceof Node\Expr\ClassConstFetch)
                    ) {
                        return false;
                    }
                }

                return true;
            }

            return false;
        }

        // $this->callback properties hold internally-assigned callables
        // (e.g. progress handlers set via setters), not request input —
        // same registry rationale as SSTI template registries.
        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
            && $expr->name instanceof Node\Identifier
        ) {
            return true;
        }

        if (!$expr instanceof Node\Expr\Array_ || $expr->items === []) {
            return false;
        }

        foreach ($expr->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem) {
                return false;
            }
            $value = $item->value;
            if (
                ($value instanceof Node\Expr\Variable && $value->name === 'this')
                || $this->isFixedCallable($value)
            ) {
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * True when every dynamic leaf of the expression was validated by
     * preg_match()/preg_match_all() in the enclosing function. Collects
     * variables used as match subjects (any argument past the pattern).
     *
     * @param list<Node> $nodes
     */
    private function isValidatedExpression(Node\Expr $expr, Node $call, array $nodes): bool
    {
        $func = $this->enclosingFunction($call, $nodes);
        if ($func === null) {
            return false;
        }

        $guarded = [];
        $matchers = $this->finder()->find($func, static function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Name
                && in_array(strtolower($node->name->toString()), ['preg_match', 'preg_match_all'], true);
        });
        foreach ($matchers as $matcher) {
            if (!$matcher instanceof Node\Expr\FuncCall) {
                continue;
            }
            foreach (array_slice($matcher->args, 1) as $arg) {
                if ($arg instanceof Node\Arg && $arg->value instanceof Node\Expr\Variable && is_string($arg->value->name)) {
                    $guarded[$arg->value->name] = true;
                }
            }
        }

        if ($guarded === []) {
            return false;
        }

        return $this->allLeavesGuarded($expr, $guarded);
    }

    /**
     * @param array<string, true> $guarded
     */
    private function allLeavesGuarded(Node\Expr $expr, array $guarded): bool
    {
        if ($this->isStaticValue($expr)) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return isset($guarded[$expr->name]);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->allLeavesGuarded($expr->left, $guarded)
                && $this->allLeavesGuarded($expr->right, $guarded);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->allLeavesGuarded($part, $guarded)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * @param list<Node> $nodes
     */
    private function enclosingFunction(
        Node $call,
        array $nodes
    ): Node\Stmt\ClassMethod|Node\Stmt\Function_|null {
        $target = spl_object_id($call);
        $funcs = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
        });

        foreach ($funcs as $func) {
            if (!$func instanceof Node\Stmt\ClassMethod && !$func instanceof Node\Stmt\Function_) {
                continue;
            }
            $found = $this->finder()->find($func, static function (Node $node) use ($target): bool {
                return spl_object_id($node) === $target;
            });
            if ($found !== []) {
                return $func;
            }
        }

        return null;
    }
}
