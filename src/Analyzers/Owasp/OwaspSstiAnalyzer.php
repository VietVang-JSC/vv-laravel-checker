<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03 Injection - Server-Side Template Injection.
 *
 * Assumes: SSTI is reported when a Blade/view rendering call receives a template argument that is not
 * a plain string literal, i.e. a variable, method call, concatenation, or interpolation that could
 * contain user input. Safe dynamic rendering with a whitelisted template key is not tracked.
 */
final class OwaspSstiAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_SSTI';

    private const STATIC_SINKS = [
        'Blade::render',
        'Illuminate\\Support\\Facades\\Blade::render',
    ];

    private const METHOD_SINKS = [
        'render', 'renderComponent', 'make', 'compileString',
    ];

    private const STATIC_COMPILE = 'compileString';

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
            return $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\FuncCall;
        });

        foreach ($calls as $call) {
            $sink = $this->resolveSink($call);
            if ($sink === null) {
                continue;
            }

            $arg = $this->templateArg($call);
            if ($arg === null || $this->isLiteralString($arg)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Potential SSTI: dynamic template argument flows into %s.', $sink),
                $file,
                $call->getStartLine(),
                Severity::Error,
                ['sink' => $sink]
            );
        }

        return $issues;
    }

    private function resolveSink(Node $node): ?string
    {
        if (
            $node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $node->name instanceof Node\Identifier
        ) {
            $class = $node->class->toString();
            $method = $node->name->toString();

            $isBlade = $class === 'Blade' || $class === 'Illuminate\\Support\\Facades\\Blade' || str_ends_with($class, '\\Blade');
            if ($isBlade && ($method === 'render' || $method === self::STATIC_COMPILE)) {
                return $class . '::' . $method;
            }
        }

        if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $method = $node->name->toString();
            if (in_array($method, self::METHOD_SINKS, true) && $this->isViewObject($node->var)) {
                return $method . '()';
            }
        }

        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = $node->name->toString();
            if (in_array($name, ['Blade', 'view'], true)) {
                $arg = $node->args[0] ?? null;
                if ($arg instanceof Node\Arg) {
                    return $name . '()';
                }
            }
        }

        return null;
    }

    private function isViewObject(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable && in_array($expr->name, ['view', 'blade'], true)) {
            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return in_array($expr->name->toString(), ['view', 'Blade'], true);
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return in_array($expr->name->toString(), ['view', 'blade'], true);
        }

        if ($expr instanceof Node\Expr\StaticCall && $expr->name instanceof Node\Identifier) {
            return $expr->name->toString() === 'make';
        }

        return false;
    }

    private function templateArg(Node $node): ?Node\Expr
    {
        $arg = $node->args[0] ?? null;

        return $arg instanceof Node\Arg ? $arg->value : null;
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

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
}
