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
 *
 * Deliberately not flagged: variables assigned a plain string literal in the same
 * function (`$view = 'backend.page'; view($view)`), which carry no user input.
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

        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }
        $scopes = $this->literalVarScopes($nodes);

        $issues = [];
        $calls = $this->finder()->find($nodes, function (Node $node): bool {
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
            if ($arg instanceof Node\Expr\Variable && $this->isLiteralVariable($arg, $call, $scopes)) {
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

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     */
    private function isLiteralVariable(Node\Expr\Variable $var, Node $call, array $scopes): bool
    {
        if (!is_string($var->name)) {
            return false;
        }

        $callId = spl_object_id($call);
        $inFunc = false;
        foreach ($scopes as $scope) {
            if ($scope['func'] === null) {
                continue;
            }
            if (!isset($scope['calls'][$callId])) {
                continue;
            }
            $inFunc = true;
            if (isset($scope['vars'][$var->name])) {
                return true;
            }
        }

        if ($inFunc) {
            return false;
        }

        foreach ($scopes as $scope) {
            if ($scope['func'] === null && isset($scope['vars'][$var->name])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scopes mapping call expressions to the string-literal variables visible in
     * the same function (plus a file-level fallback for top-level code).
     *
     * @param list<Node> $nodes
     * @return list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}>
     */
    private function literalVarScopes(array $nodes): array
    {
        $scopes = [];
        $funcs = $this->finder()->find($nodes, function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
        });

        foreach ($funcs as $func) {
            if (!$func instanceof Node\Stmt\ClassMethod && !$func instanceof Node\Stmt\Function_) {
                continue;
            }
            $calls = [];
            foreach (
                $this->finder()->find($func, static function (Node $node): bool {
                    return $node instanceof Node\Expr\StaticCall
                    || $node instanceof Node\Expr\MethodCall
                    || $node instanceof Node\Expr\FuncCall;
                }) as $call
            ) {
                $calls[spl_object_id($call)] = true;
            }
            $scopes[] = ['func' => spl_object_id($func), 'vars' => $this->literalAssignedVars($func), 'calls' => $calls];
        }

        $scopes[] = ['func' => null, 'vars' => $this->literalAssignedVars($nodes), 'calls' => []];

        return $scopes;
    }

    /**
     * @param Node|list<Node> $scope
     * @return array<string, true>
     */
    private function literalAssignedVars(Node|array $scope): array
    {
        $vars = [];
        $assigns = $this->finder()->find($scope, static function (Node $node): bool {
            return $node instanceof Node\Expr\Assign;
        });
        foreach ($assigns as $assign) {
            if (
                $assign instanceof Node\Expr\Assign
                && $assign->var instanceof Node\Expr\Variable
                && is_string($assign->var->name)
                && $assign->expr instanceof Node\Scalar\String_
            ) {
                $vars[$assign->var->name] = true;
            }
        }

        return $vars;
    }
}
