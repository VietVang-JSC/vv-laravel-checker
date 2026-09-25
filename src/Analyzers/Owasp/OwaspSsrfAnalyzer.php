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
 *
 * Deliberately not flagged: sinks inside test paths, `fopen()` in a write/append
 * mode (local file creation, not a server-side request), and arguments that look
 * like local filesystem paths (path/file/source/target names or Laravel path
 * helpers such as storage_path()/base_path()).
 */
final class OwaspSsrfAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_SSRF';

    private const FUNC_SINKS = ['file_get_contents', 'fopen', 'curl_init', 'get_headers'];

    private const METHOD_SINKS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'request', 'send'];

    private const PATH_HELPERS = [
        'storage_path', 'base_path', 'public_path', 'resource_path',
        'database_path', 'app_path', 'config_path', 'lang_path',
    ];

    private const CONFIG_FUNCS = ['env', 'config'];

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
            if ($this->isTestPath($file)) {
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
        $origins = $this->variableOrigins($nodes);

        $issues = [];
        $calls = $this->finder()->find($nodes, function (Node $node): bool {
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

            if ($sink === 'fopen()' && $this->isWriteModeOpen($call)) {
                continue;
            }

            $urlArg = $this->firstUrlArg($call, $sink);
            if ($urlArg === null) {
                continue;
            }

            if (!$this->isPotentialUserInput($urlArg, $origins)) {
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

        // Guzzle-style request(method, url, options): the URL is the second
        // argument, not the first.
        if (
            $sink === 'request()'
            && ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
        ) {
            $arg = $args[1] ?? $args[0] ?? null;

            return $arg instanceof Node\Arg ? $arg->value : null;
        }

        $arg = $args[0] ?? null;

        if ($node instanceof Node\Expr\FuncCall && in_array($sink, ['file_get_contents()', 'fopen()', 'get_headers()'], true)) {
            return $arg instanceof Node\Arg ? $arg->value : null;
        }

        if ($arg instanceof Node\Arg) {
            return $arg->value;
        }

        return null;
    }

    /**
     * @param array<string, list<Node\Expr>> $origins
     */
    private function isPotentialUserInput(Node\Expr $expr, array $origins): bool
    {
        if ($this->isLiteralString($expr)) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\Variable
            && is_string($expr->name)
            && $this->isSafeVariable($expr->name, $origins, [])
        ) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), self::CONFIG_FUNCS, true)
        ) {
            return false;
        }

        if ($this->isDeployTimeExpr($expr, $origins, [])) {
            return false;
        }

        if ($this->isLocalPath($expr)) {
            return false;
        }

        if ($this->hasFixedHost($expr)) {
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

    /**
     * A URL whose host part is a string literal cannot be steered off-site:
     * only path/query remain dynamic, which is not SSRF. Matches
     * `https://literal-host/...` built by concat, interpolation, or sprintf()
     * with a literal format. A dynamic subdomain (`https://$lang.host/...`)
     * does NOT match and stays flagged.
     */
    private function hasFixedHost(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->toString()) === 'sprintf'
        ) {
            $format = $expr->args[0] ?? null;
            if (!$format instanceof Node\Arg || !$format->value instanceof Node\Scalar\String_) {
                return false;
            }

            return $this->isFixedHostPrefix($format->value->value);
        }

        return $this->isFixedHostPrefix($this->leadingLiteral($expr));
    }

    private function isFixedHostPrefix(string $prefix): bool
    {
        return preg_match('#^https?://[^/$\s]+\/#i', $prefix) === 1;
    }

    private function leadingLiteral(Node\Expr $expr): string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $left = $this->leadingLiteral($expr->left);
            if ($left === '') {
                return '';
            }
            $right = $expr->right instanceof Node\Scalar\String_ ? $expr->right->value : '';

            return $left . $right;
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            $out = '';
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr) {
                    break;
                }
                $out .= $part->value;
            }

            return $out;
        }

        return '';
    }

    private function isWriteModeOpen(Node $node): bool
    {
        if (!$node instanceof Node\Expr\FuncCall) {
            return false;
        }
        $mode = $node->args[1] ?? null;
        if (!$mode instanceof Node\Arg || !$mode->value instanceof Node\Scalar\String_) {
            return false;
        }

        return (bool) preg_match('/^[waxc]/i', ltrim($mode->value->value));
    }

    /**
     * Deploy-time expressions: literals, env()/config() lookups, string
     * helpers (trim/sprintf/...) applied to deploy-time values, and variables
     * assigned only such expressions (e.g. `$base = rtrim(env('API_URL'), '/')`).
     *
     * @param array<string, list<Node\Expr>> $origins
     * @param array<string, true> $seen cycle guard
     */
    private function isDeployTimeExpr(Node\Expr $expr, array $origins, array $seen): bool
    {
        if ($this->isLiteralString($expr)) {
            return true;
        }

        if ($expr instanceof Node\Expr\ConstFetch || $expr instanceof Node\Expr\ClassConstFetch) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            if (isset($seen[$expr->name])) {
                return false;
            }
            $seen[$expr->name] = true;
            $rhsList = $origins[$expr->name] ?? [];
            if ($rhsList === []) {
                return false;
            }
            foreach ($rhsList as $rhs) {
                if (!$this->isDeployTimeExpr($rhs, $origins, $seen)) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->toString());
            if (in_array($fn, self::CONFIG_FUNCS, true)) {
                return true;
            }
            if (!in_array($fn, ['trim', 'ltrim', 'rtrim', 'sprintf'], true)) {
                return false;
            }
            foreach ($expr->args as $arg) {
                if ($arg instanceof Node\Arg && !$this->isDeployTimeExpr($arg->value, $origins, $seen)) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isDeployTimeExpr($expr->left, $origins, $seen)
                && $this->isDeployTimeExpr($expr->right, $origins, $seen);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->isDeployTimeExpr($part, $origins, $seen)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * A variable is safe when it has at least one assignment and every
     * assignment is a safe origin (literal, fixed-host URL, local path,
     * deploy-time config). Any dynamic reassignment keeps it flagged.
     *
     * @param array<string, list<Node\Expr>> $origins
     * @param array<string, true> $seen cycle guard
     */
    private function isSafeVariable(string $name, array $origins, array $seen): bool
    {
        if (isset($seen[$name])) {
            return false;
        }
        $seen[$name] = true;

        $rhsList = $origins[$name] ?? [];
        if ($rhsList === []) {
            return false;
        }

        foreach ($rhsList as $rhs) {
            if ($rhs instanceof Node\Expr\Variable && is_string($rhs->name)) {
                if (!$this->isSafeVariable($rhs->name, $origins, $seen)) {
                    return false;
                }
                continue;
            }
            if (!$this->isLiteralString($rhs) && !$this->hasFixedHost($rhs) && !$this->isLocalPath($rhs)) {
                return false;
            }
        }

        return true;
    }

    private function isLocalPath(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), self::PATH_HELPERS, true)
        ) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && $this->rootVariableName($expr) !== 'request'
            && $this->isLocalPathName($expr->name->toString())
        ) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\StaticCall
            && $expr->name instanceof Node\Identifier
            && $expr->class instanceof Node\Name
        ) {
            $class = strtolower(ltrim($expr->class->toString(), '\\'));
            if ($class === 'request' || str_ends_with($class, '\\request')) {
                return false;
            }
            if ($this->isLocalPathName($expr->name->toString())) {
                return true;
            }
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            if ($this->rootVariableName($expr) === 'request') {
                return false;
            }

            return $this->isLocalPathName($expr->name);
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            if ($this->rootVariableName($expr) === 'request') {
                return false;
            }

            return $this->isLocalPathName($expr->name->toString());
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isLocalPathOperand($expr->left) && $this->isLocalPathOperand($expr->right);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->isLocalPathOperand($part)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    private function isLocalPathOperand(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Scalar\String_ || $this->isLocalPath($expr);
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
