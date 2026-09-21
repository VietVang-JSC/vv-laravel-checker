<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class LaravelTaintAnalyzer
{
    private const RULE = 'LARAVEL_TAINT';

    private const RAW_SINKS = [
        'whereRaw',
        'selectRaw',
        'orderByRaw',
        'havingRaw',
        'groupByRaw',
        'raw',
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

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    public function analyzeFile(string $file): array
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
        $finder = new NodeFinder();

        foreach ($finder->findInstanceOf($ast, Node\Expr\MethodCall::class) as $call) {
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
            if ($method !== null && in_array($method, self::RAW_SINKS, true)) {
                foreach ($call->args as $arg) {
                    $value = $arg->value;
                    if ($this->containsTaintedNode($value)) {
                        $issues[] = new Issue(
                            self::RULE,
                            sprintf('Tainted user input is interpolated into raw query call ->%s().', $method),
                            $file,
                            $call->getStartLine(),
                            Severity::Error,
                            'custom',
                            ['method' => $method]
                        );
                        break;
                    }
                }
            }
        }

        return $issues;
    }

    private function containsTaintedNode(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->isTaintedExpr($part)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsTaintedNode($expr->left) || $this->containsTaintedNode($expr->right);
        }

        if ($expr instanceof Node\Scalar\String_) {
            foreach ($expr->parts ?? [] as $part) {
                if ($part instanceof Node\Expr && $this->isTaintedExpr($part)) {
                    return true;
                }
            }
        }

        return $this->isTaintedExpr($expr);
    }

    private function isTaintedExpr(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable) {
            return in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', 'request', 'req'], true);
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            $method = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            if (in_array($method, ['input', 'query', 'get', 'post', 'all', 'only', 'except', 'cookie', 'header'], true)) {
                return $this->isRequestObject($expr->var);
            }

            return false;
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $expr->name instanceof Node\Name ? $expr->name->toString() : null;

            return in_array($name, ['input', 'request', 'all'], true)
                || in_array($name, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true);
        }

        if ($expr instanceof Node\Expr\PropertyFetch) {
            return $expr->name instanceof Node\Identifier
                && $expr->name->toString() === 'request'
                && $this->isRequestObject($expr->var);
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return $this->isTaintedExpr($expr->var);
        }

        if ($expr instanceof Node\Expr\BinaryOp) {
            return $this->isTaintedExpr($expr->left) || $this->isTaintedExpr($expr->right);
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

    private function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }

    private function parse(string $code): ?array
    {
        try {
            $parser = (new ParserFactory())->createForNewestSupportedVersion();

            return $parser->parse($code);
        } catch (\Throwable $e) {
            return null;
        }
    }
}
