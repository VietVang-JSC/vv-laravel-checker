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
