<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03 Injection - Command Injection.
 *
 * Assumes: OS command sinks are flagged when an argument is user input (request/input/superglobal) or
 * a tainted variable/expression. Relies on AbstractAnalyzer::isTaintedExpr plus explicit input shape
 * detection; this is a heuristic without cross-function data-flow tracking.
 */
final class OwaspCommandInjectionAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_COMMAND_INJECTION';

    private const FUNC_SINKS = ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'];

    private const PROCESS_CLASS = 'Symfony\\Component\\Process\\Process';

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
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\New_;
        });

        foreach ($calls as $call) {
            if ($call instanceof Node\Expr\FuncCall) {
                if (!$call->name instanceof Node\Name) {
                    continue;
                }
                $fn = $call->name->toString();
                if (!in_array($fn, self::FUNC_SINKS, true)) {
                    continue;
                }

                $arg = $call->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isUserInput($arg->value)) {
                    continue;
                }

                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential command injection: user input flows into %s().', $fn),
                    $file,
                    $call->getStartLine(),
                    Severity::Critical,
                    ['sink' => $fn . '()']
                );
                continue;
            }

            if (
                $call instanceof Node\Expr\New_
                && $call->class instanceof Node\Name
                && in_array($call->class->toString(), [self::PROCESS_CLASS, '\\' . self::PROCESS_CLASS, 'Process'], true)
            ) {
                foreach ($call->args as $arg) {
                    if ($arg instanceof Node\Arg && $this->isUserInput($arg->value)) {
                        $issues[] = $this->makeIssue(
                            self::RULE,
                            'Potential command injection: user input flows into Symfony Process.',
                            $file,
                            $call->getStartLine(),
                            Severity::Critical,
                            ['sink' => 'new Process()']
                        );
                        break;
                    }
                }
            }
        }

        return $issues;
    }

    private function isUserInput(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->isUserInput($part)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isUserInput($expr->left) || $this->isUserInput($expr->right);
        }

        if ($this->isTaintedExpr($expr)) {
            return true;
        }

        return false;
    }
}
