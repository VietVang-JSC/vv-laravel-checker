<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class SqlInjectionAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'SQL_INJECTION';

    private const RAW_METHODS = [
        'select',
        'statement',
        'unprepared',
        'raw',
        'selectRaw',
        'whereRaw',
        'orderByRaw',
        'havingRaw',
        'groupByRaw',
    ];

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
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall;
        });

        foreach ($calls as $call) {
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
            if ($method === null || !in_array($method, self::RAW_METHODS, true)) {
                continue;
            }

            if (!$this->isDbContext($call)) {
                continue;
            }

            foreach ($call->args as $arg) {
                if ($this->containsTaintedInput($arg->value)) {
                    $issues[] = $this->makeIssue(
                        self::RULE,
                        sprintf('Potential SQL injection: tainted input flows into %s().', $method),
                        $file,
                        $call->getStartLine(),
                        Severity::Critical,
                        ['method' => $method]
                    );
                    break;
                }
            }
        }

        return $issues;
    }

    private function isDbContext(Node $call): bool
    {
        if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name) {
            $class = $call->class->toString();

            return $class === 'DB' || str_ends_with($class, '\\DB');
        }

        if ($call instanceof Node\Expr\MethodCall) {
            $var = $call->var;
            if (
                $var instanceof Node\Expr\StaticCall
                && $var->class instanceof Node\Name
                && in_array($var->class->toString(), ['DB', 'Illuminate\\Support\\Facades\\DB'], true)
            ) {
                return true;
            }

            return $this->mentionsDb($var);
        }

        return false;
    }

    private function mentionsDb(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->mentionsDb($expr->var);
        }

        if ($expr instanceof Node\Expr\Variable && $expr->name === 'db') {
            return true;
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier && $expr->name->toString() === 'db') {
            return true;
        }

        return false;
    }

    private function containsTaintedInput(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->looksLikeInput($part)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsTaintedInput($expr->left) || $this->containsTaintedInput($expr->right);
        }

        if ($expr instanceof Node\Scalar\String_ && isset($expr->parts)) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->looksLikeInput($part)) {
                    return true;
                }
            }

            return false;
        }

        return $this->looksLikeInput($expr);
    }

    private function looksLikeInput(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $expr->name instanceof Node\Name ? $expr->name->toString() : null;
            if (in_array($name, ['input', 'request', 'all', 'get', 'post', 'cookie'], true)) {
                return true;
            }

            if (in_array($name, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true)) {
                return true;
            }

            return false;
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            $method = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            if (in_array($method, ['input', 'query', 'get', 'post', 'all', 'only', 'except', 'cookie', 'header'], true)) {
                return $this->isRequestObject($expr->var);
            }

            return false;
        }

        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && in_array($expr->name->toString(), ['all', 'input', 'query'], true)
        ) {
            return $this->isRequestObject($expr->var);
        }

        if ($expr instanceof Node\Expr\Variable && in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_ENV'], true)) {
            return true;
        }

        return false;
    }

    private function isRequestObject(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable && $expr->name === 'request') {
            return true;
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

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && $expr->name->toString() === 'request'
        ) {
            return true;
        }

        return false;
    }
}
