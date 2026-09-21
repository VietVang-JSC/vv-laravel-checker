<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class UnsafeEvalAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'UNSAFE_EVAL';

    private const FUNCTIONS = ['eval', 'assert', 'create_function'];

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

        $issues = [];
        $calls = $this->finder()->findInstanceOf($ast, Node\Expr\FuncCall::class);
        $evals = $this->finder()->findInstanceOf($ast, Node\Expr\Eval_::class);

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
}
