<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A01 Open Redirect.
 *
 * Assumes: the target of a redirect sink is attacker-controlled unless it is a
 * string literal/constant, a named-route/back call, a url()->previous() lookup,
 * or a deploy-time config()/env() lookup. Concatenated or interpolated targets
 * are safe only when every leaf is safe by that definition. This is a
 * heuristic, not a full data-flow analysis.
 *
 * Deliberately not flagged: Redirect::route(...) / redirect()->route(...),
 * back() / redirect()->back(), string literals, and config()/env()-based
 * targets (e.g. redirect(config('app.url') . '/done')).
 *
 * Confidence: a bare variable/array access, function call, or dynamic string
 * is High (typically a request return-url); a method/property/static target
 * such as redirect($page->getUrl()) is Medium — usually an internal URL
 * builder, but not provably safe without cross-method analysis.
 */
final class OwaspOpenRedirectAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_OPEN_REDIRECT';

    /**
     * Redirect-target helpers that provably stay on known-safe destinations.
     * `url` is only safe with safe arguments (rechecked below) because
     * `url($userInput)` can still point off-site.
     */
    private const SAFE_FUNCS = ['route', 'back', 'config', 'env', 'url'];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isTestPath($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @return Issue[]
     */
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
        $known = $this->safeTargetVars($nodes);

        $issues = [];
        $calls = $this->finder()->find($nodes, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall;
        });

        foreach ($calls as $call) {
            $sink = $this->resolveSink($call);
            if ($sink === null) {
                continue;
            }

            [$label, $target] = $sink;
            if ($target === null) {
                continue;
            }
            if ($this->isSafeTarget($target, $known)) {
                continue;
            }
            if (!$this->isFlaggableTarget($target)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Potential open redirect: user-controlled target flows into %s.', $label),
                $file,
                $call->getStartLine(),
                Severity::Error,
                ['sink' => $label],
                $this->isDirectTarget($target) ? Confidence::High : Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * Bare variables, function calls and dynamic strings are typically request
     * return-urls (High); method/property/static targets are usually internal
     * URL builders (Medium) — unless they read the request directly, e.g.
     * redirect($request->input('next')).
     */
    private function isDirectTarget(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\Variable
            || $expr instanceof Node\Expr\ArrayDimFetch
            || $expr instanceof Node\Expr\FuncCall
            || $expr instanceof Node\Expr\BinaryOp\Concat
            || $expr instanceof Node\Scalar\InterpolatedString
            || $expr instanceof Node\Expr\Ternary
            || $expr instanceof Node\Expr\BinaryOp\Coalesce
        ) {
            return true;
        }

        return $this->readsRequest($expr);
    }

    /**
     * Detect direct request reads: $request, request(...), ->input()/query()/
     * cookie()/header() accessors.
     */
    private function readsRequest(Node\Expr $expr): bool
    {
        $found = $this->finder()->find($expr, static function (Node $node): bool {
            if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
                return strtolower($node->name) === 'request';
            }
            if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                return strtolower($node->name->toString()) === 'request';
            }
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array(strtolower($node->name->toString()), ['input', 'query', 'cookie', 'header'], true);
            }

            return false;
        });

        return $found !== [];
    }

    /**
     * @return array{string, Node\Expr|null}|null sink label plus redirect target
     */
    private function resolveSink(Node $node): ?array
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            if (strtolower($node->name->toString()) !== 'redirect') {
                return null;
            }
            $arg = $node->args[0] ?? null;

            return ['redirect()', $arg instanceof Node\Arg ? $arg->value : null];
        }

        if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $method = strtolower($node->name->toString());
            if ($method === 'route' || $method === 'back') {
                return null;
            }
            if ($method !== 'away' && $method !== 'to') {
                return null;
            }
            if (!$this->isRedirectReceiver($node->var)) {
                return null;
            }
            $arg = $node->args[0] ?? null;

            return ['redirect()->' . $method . '()', $arg instanceof Node\Arg ? $arg->value : null];
        }

        if ($node instanceof Node\Expr\StaticCall && $node->name instanceof Node\Identifier) {
            $method = strtolower($node->name->toString());
            if ($method === 'route' || $method === 'back') {
                return null;
            }
            if ($method !== 'away' && $method !== 'to') {
                return null;
            }
            if (!$node->class instanceof Node\Name || !$this->isRedirectClass($node->class->toString())) {
                return null;
            }
            $arg = $node->args[0] ?? null;

            return ['Redirect::' . $method . '()', $arg instanceof Node\Arg ? $arg->value : null];
        }

        return null;
    }

    private function isRedirectReceiver(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return strtolower($expr->name->toString()) === 'redirect';
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isRedirectReceiver($expr->var);
        }

        if ($expr instanceof Node\Expr\StaticCall) {
            return $expr->class instanceof Node\Name && $this->isRedirectClass($expr->class->toString());
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), ['redirect', 'redirector'], true);
        }

        return false;
    }

    private function isRedirectClass(string $class): bool
    {
        $normalized = strtolower(ltrim($class, '\\'));
        $parts = explode('\\', $normalized);
        $base = (string) end($parts);

        return $base === 'redirect' || $base === 'redirector';
    }

    /**
     * Variables assigned deploy-time-safe redirect targets in source order
     * (`$login = config('app.url') . '/login'`), so sinks using the variable
     * are recognized as safe.
     *
     * @param list<Node> $nodes
     * @return array<string, true>
     */
    private function safeTargetVars(array $nodes): array
    {
        $known = [];
        $assigns = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Assign;
        });
        foreach ($assigns as $assign) {
            if (
                $assign instanceof Node\Expr\Assign
                && $assign->var instanceof Node\Expr\Variable
                && is_string($assign->var->name)
                && $this->isSafeTarget($assign->expr, $known)
            ) {
                $known[$assign->var->name] = true;
            }
        }

        return $known;
    }

    /**
     * @param array<string, true> $known
     */
    private function isSafeTarget(Node\Expr $expr, array $known = []): bool
    {
        if (
            $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Scalar\LNumber
            || $expr instanceof Node\Scalar\DNumber
            || $expr instanceof Node\Expr\ConstFetch
            || $expr instanceof Node\Expr\ClassConstFetch
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return isset($known[$expr->name]);
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), self::SAFE_FUNCS, true)
        ) {
            if (strtolower($expr->name->toString()) === 'url') {
                foreach ($expr->args as $arg) {
                    if ($arg instanceof Node\Arg && !$this->isSafeTarget($arg->value, $known)) {
                        return false;
                    }
                }
            }

            return true;
        }

        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'previous'
            && $this->isUrlHelper($expr->var)
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isSafeTarget($expr->left, $known) && $this->isSafeTarget($expr->right, $known);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->isSafeTarget($part, $known)) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\Ternary) {
            if ($expr->if !== null && !$this->isSafeTarget($expr->if, $known)) {
                return false;
            }

            return $this->isSafeTarget($expr->else, $known);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->isSafeTarget($expr->left, $known) && $this->isSafeTarget($expr->right, $known);
        }

        return false;
    }

    private function isUrlHelper(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return strtolower($expr->name->toString()) === 'url';
        }

        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name) {
            $segments = explode('\\', ltrim($expr->class->toString(), '\\'));
            $base = strtolower((string) end($segments));

            return $base === 'url';
        }

        return false;
    }

    private function isFlaggableTarget(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\BinaryOp\Concat
            || $expr instanceof Node\Scalar\InterpolatedString
            || $expr instanceof Node\Expr\StaticCall
            || $expr instanceof Node\Expr\New_
            || $expr instanceof Node\Expr\Ternary
        ) {
            return true;
        }

        return $this->isTaintedExpr($expr);
    }
}
