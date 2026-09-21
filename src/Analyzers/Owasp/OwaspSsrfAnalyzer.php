<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A10/A09 Server-Side Request Forgery.
 *
 * Assumes: SSRF sinks are flagged when their URL argument is a variable, a property/method call, or
 * a concat/interpolation that resolves to user input. URL variables not conclusively user-derived are
 * flagged when the sink receives a non-literal argument. This is a heuristic, not a full data-flow analysis.
 */
final class OwaspSsrfAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_SSRF';

    private const FUNC_SINKS = ['file_get_contents', 'fopen', 'curl_init', 'get_headers'];

    private const METHOD_SINKS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'request', 'send'];

    private const STATIC_CLIENTS = [
        'Http',
        'Illuminate\\Support\\Facades\\Http',
        'Client',
        'GuzzleHttp\\Client',
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
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\New_;
        });

        foreach ($calls as $call) {
            $sink = $this->resolveSink($call);
            if ($sink === null) {
                continue;
            }

            $urlArg = $this->firstUrlArg($call, $sink);
            if ($urlArg === null) {
                continue;
            }

            if (!$this->isPotentialUserInput($urlArg)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Potential SSRF: URL derived from user input flows into %s.', $sink),
                $file,
                $call->getStartLine(),
                Severity::Error,
                ['sink' => $sink]
            );
        }

        return $issues;
    }

    /**
     * @return string|null sink label
     */
    private function resolveSink(Node $node): ?string
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $fn = $node->name->toString();
            if (in_array($fn, self::FUNC_SINKS, true)) {
                return $fn . '()';
            }
        }

        if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $method = $node->name->toString();
            if (!in_array($method, self::METHOD_SINKS, true)) {
                return null;
            }
            if ($this->isHttpClientVar($node->var)) {
                return $method . '()';
            }
        }

        if ($node instanceof Node\Expr\StaticCall && $node->name instanceof Node\Identifier) {
            $method = $node->name->toString();
            if (!in_array($method, self::METHOD_SINKS, true)) {
                return null;
            }
            if ($node->class instanceof Node\Name && $this->isHttpClientClass($node->class->toString())) {
                return $method . '()';
            }
        }

        if (
            $node instanceof Node\Expr\New_
            && $node->class instanceof Node\Name
            && in_array($node->class->toString(), ['GuzzleHttp\\Client', 'Client', '\\GuzzleHttp\\Client'], true)
        ) {
            return 'new GuzzleHttp\Client()';
        }

        return null;
    }

    private function isHttpClientVar(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable) {
            return in_array($expr->name, ['client', 'http', 'guzzle'], true);
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return in_array($expr->name->toString(), ['client', 'http', 'guzzle'], true);
        }

        return false;
    }

    private function isHttpClientClass(string $class): bool
    {
        foreach (self::STATIC_CLIENTS as $candidate) {
            if ($class === $candidate) {
                return true;
            }
        }

        return false;
    }

    private function firstUrlArg(Node $node, string $sink): ?Node\Expr
    {
        $args = $node->args;
        $arg = $args[0] ?? null;

        if ($node instanceof Node\Expr\FuncCall && in_array($sink, ['file_get_contents()', 'fopen()', 'get_headers()'], true)) {
            return $arg instanceof Node\Arg ? $arg->value : null;
        }

        if ($arg instanceof Node\Arg) {
            return $arg->value;
        }

        return null;
    }

    private function isPotentialUserInput(Node\Expr $expr): bool
    {
        if ($this->isLiteralString($expr)) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\BinaryOp\Concat
            || $expr instanceof Node\Scalar\InterpolatedString
        ) {
            return true;
        }

        return $this->isTaintedExpr($expr);
    }

    private function isLiteralString(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return true;
        }

        if ($expr instanceof Node\Expr\ConstFetch) {
            return true;
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            return true;
        }

        return false;
    }
}
