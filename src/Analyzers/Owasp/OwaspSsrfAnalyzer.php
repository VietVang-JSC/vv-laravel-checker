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
 * Sinks: file_get_contents()/fopen()/curl_init()/get_headers()/copy()/
 * readfile()/file()/fsockopen()/pfsockopen()/stream_socket_client(), HTTP
 * client get/post/put/patch/delete/head/request/send (including `?->`
 * nullsafe calls), curl_setopt($ch, CURLOPT_URL, $url), and Http/Client
 * static calls.
 * Assumes: SSRF sinks are flagged when their URL argument is a variable, a property/method call, or
 * a concat/interpolation that resolves to user input. For Guzzle-style
 * `request($method, $url)` the URL is read from the second argument; named
 * `url:`/`uri:`/`path:` arguments win over position. URL variables not conclusively user-derived are
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

    private const FUNC_SINKS = ['file_get_contents', 'fopen', 'curl_init', 'get_headers', 'copy', 'readfile', 'file', 'fsockopen', 'pfsockopen', 'stream_socket_client'];

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
        // Loop-carried origins are invisible to the shared assignment scan:
        // foreach ($files as $file) and $uploads['k'] = glob(...) must map
        // the loop variable / array to its source expression, otherwise
        // directory listings look like unknown (flaggable) input.
        foreach ($this->loopOrigins($nodes) as $name => $rhsList) {
            foreach ($rhsList as $rhs) {
                $origins[$name][] = $rhs;
            }
        }
        $sanitizedScopes = $this->sanitizedVarScopes($nodes);

        $issues = [];
        $calls = $this->finder()->find($nodes, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\NullsafeMethodCall
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

            if (!$this->isPotentialUserInput($urlArg, $origins, $call, $sanitizedScopes)) {
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
            if ($fn === 'curl_setopt') {
                return 'curl_setopt()';
            }
        }

        if (
            $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\NullsafeMethodCall
        ) {
            if (!$node->name instanceof Node\Identifier) {
                return null;
            }
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

        // Named arguments win: $client->get(url: $u).
        foreach ($args as $arg) {
            if (
                $arg instanceof Node\Arg
                && $arg->name instanceof Node\Identifier
                && in_array(strtolower($arg->name->toString()), ['url', 'uri', 'path'], true)
            ) {
                return $arg->value;
            }
        }

        // Guzzle-style request(method, url, options): the URL is the second
        // argument, not the first.
        if (
            $sink === 'request()'
            && ($node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\NullsafeMethodCall
                || $node instanceof Node\Expr\StaticCall)
        ) {
            $arg = $args[1] ?? $args[0] ?? null;

            return $arg instanceof Node\Arg ? $arg->value : null;
        }

        // curl_setopt($ch, CURLOPT_URL, $url): only the URL option is a sink.
        if (
            $sink === 'curl_setopt()'
            && $node instanceof Node\Expr\FuncCall
        ) {
            $option = $args[1] ?? null;
            if (
                !$option instanceof Node\Arg
                || !$option->value instanceof Node\Expr\ConstFetch
                || !$option->value->name instanceof Node\Name
                || $option->value->name->toString() !== 'CURLOPT_URL'
            ) {
                return null;
            }
            $arg = $args[2] ?? null;

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
    /**
     * @param array<string, list<Node\Expr>> $origins
     * @param array<int, array<string, true>> $sanitizedScopes call id => sanitized var names
     */
    private function isPotentialUserInput(Node\Expr $expr, array $origins, ?Node $call = null, array $sanitizedScopes = []): bool
    {
        // $files[$i] carries the safety of $files (directory listings,
        // deploy-time arrays, ...): judge the base expression.
        while ($expr instanceof Node\Expr\ArrayDimFetch) {
            $expr = $expr->var;
        }

        if ($this->isDirectoryListing($expr)) {
            return false;
        }

        if ($this->isLiteralString($expr)) {
            return false;
        }

        // Validator-gated in the same function: if (!sanitizeRemoteUrl($url))
        // throw ...; get_headers($url). The sanitizer, not the sink, decides.
        if (
            $expr instanceof Node\Expr\Variable
            && is_string($expr->name)
            && $call instanceof Node
            && isset($sanitizedScopes[spl_object_id($call)][$expr->name])
        ) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\Variable
            && is_string($expr->name)
            && $this->isSafeVariable($expr->name, $origins, [])
        ) {
            return false;
        }

        // $this->apiUrl assigned only deploy-time values (typically
        // env()/config() in the constructor) is deploy-time, not input.
        // Any dynamic assignment keeps it flaggable.
        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
            && $expr->name instanceof Node\Identifier
            && $this->isDeployTimeProperty($expr->name->toString(), $origins, [])
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
            // Every dynamic leaf provably safe (literals aside) — e.g.
            // 'themes/' . $entry with $entry from readdir(). Any unknown
            // leaf keeps the flag.
            if ($this->allConcatVarsSafe($expr, $origins)) {
                return false;
            }

            return true;
        }

        return $this->isTaintedExpr($expr);
    }

    /**
     * Every $variable leaf of a concatenation/interpolation resolves to a
     * safe origin (deploy-time, local path, directory listing, ...).
     *
     * @param array<string, list<Node\Expr>> $origins
     */
    private function allConcatVarsSafe(Node\Expr $expr, array $origins): bool
    {
        $seen = [];
        $vars = $this->finder()->find($expr, static function (Node $node): bool {
            return $node instanceof Node\Expr\Variable;
        });
        foreach ($vars as $var) {
            if (!$var instanceof Node\Expr\Variable || !is_string($var->name)) {
                return false;
            }
            if (isset($seen[$var->name])) {
                continue;
            }
            $seen[$var->name] = true;
            if (!$this->isSafeVariable($var->name, $origins, [])) {
                return false;
            }
        }

        return $seen !== [];
    }

    /**
     * Extra origins the assignment scan misses: foreach value/key variables
     * (`foreach ($files as $file)` maps $file to $files), array-element
     * assignments (`$uploads['k'] = glob(...)`), and `$this->prop = ...`
     * property assignments (deploy-time config typically lands in
     * properties: `$this->apiUrl = env('EMS_URL')`). Only adds origins
     * (silencing direction) — never removes any.
     *
     * @param list<Node> $nodes
     * @return array<string, list<Node\Expr>>
     */
    private function loopOrigins(array $nodes): array
    {
        $origins = [];
        $loops = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Foreach_
                || $node instanceof Node\Expr\Assign
                || $node instanceof Node\Stmt\Property;
        });
        foreach ($loops as $node) {
            if ($node instanceof Node\Stmt\Property) {
                foreach ($node->props as $prop) {
                    if (
                        $prop instanceof Node\Stmt\PropertyProperty
                        && $prop->default instanceof Node\Expr
                    ) {
                        $origins['this->' . $prop->name->toString()][] = $prop->default;
                    }
                }
                continue;
            }
            if ($node instanceof Node\Stmt\Foreach_) {
                if ($node->valueVar instanceof Node\Expr\Variable && is_string($node->valueVar->name)) {
                    $origins[$node->valueVar->name][] = $node->expr;
                }
                if ($node->keyVar instanceof Node\Expr\Variable && is_string($node->keyVar->name)) {
                    $origins[$node->keyVar->name][] = $node->expr;
                }
                continue;
            }
            if (
                $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\ArrayDimFetch
                && $node->var->var instanceof Node\Expr\Variable
                && is_string($node->var->var->name)
            ) {
                $origins[$node->var->var->name][] = $node->expr;
            }
            if (
                $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\PropertyFetch
                && $node->var->var instanceof Node\Expr\Variable
                && $node->var->var->name === 'this'
            ) {
                // PropertyFetch->name is natively Node; dynamic property
                // names ($this->$var) are not tracked as origins.
                /** @var Node\Identifier|Node\Expr $propName */
                $propName = $node->var->name;
                if ($propName instanceof Node\Identifier) {
                    $origins['this->' . $propName->toString()][] = $node->expr;
                }
            }
        }

        return $origins;
    }

    /**
     * Directory listings return server-side paths, never remote URLs:
     * glob()/scandir()/readdir(), Storage::files()/allFiles(), File::files().
     */
    private function isDirectoryListing(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), ['glob', 'scandir', 'readdir'], true)
        ) {
            return true;
        }

        if (
            ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall)
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), ['files', 'allfiles', 'listcontents'], true)
        ) {
            return true;
        }

        return false;
    }

    /**
     * Variables passed through a *sanitiz*() gate in the same scope
     * (`if (!sanitizeRemoteUrl($url)) throw ...;`), so a later sink using
     * them is reviewed-by-construction. Scoped per function (plus top-level)
     * so a gate in one function never silences another.
     *
     * @param list<Node> $nodes
     * @return array<int, array<string, true>> call id => sanitized var names
     */
    private function sanitizedVarScopes(array $nodes): array
    {
        $funcs = [];
        foreach (
            $this->finder()->find($nodes, static function (Node $node): bool {
                return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
            }) as $func
        ) {
            if ($func instanceof Node\Stmt\ClassMethod || $func instanceof Node\Stmt\Function_) {
                $funcs[] = $func;
            }
        }

        $byCall = [];
        $scopes = array_merge($funcs, [null]);
        foreach ($scopes as $scope) {
            $haystack = $scope ?? $nodes;
            $names = [];
            $gates = $this->finder()->find($haystack, static function (Node $node): bool {
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                    return str_contains(strtolower($node->name->toString()), 'sanitiz');
                }
                if (
                    ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
                    && $node->name instanceof Node\Identifier
                ) {
                    return str_contains(strtolower($node->name->toString()), 'sanitiz');
                }

                return false;
            });
            foreach ($gates as $gate) {
                if (
                    !$gate instanceof Node\Expr\FuncCall
                    && !$gate instanceof Node\Expr\MethodCall
                    && !$gate instanceof Node\Expr\StaticCall
                ) {
                    continue;
                }
                if ($scope === null && $this->isInsideAnyFunction($gate, $funcs)) {
                    continue;
                }
                foreach ($gate->args as $arg) {
                    if (!$arg instanceof Node\Arg) {
                        continue;
                    }
                    $vars = $this->finder()->find($arg->value, static function (Node $node): bool {
                        return $node instanceof Node\Expr\Variable;
                    });
                    foreach ($vars as $var) {
                        if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
                            $names[$var->name] = true;
                        }
                    }
                }
            }
            if ($names === []) {
                continue;
            }
            $calls = $this->finder()->find($haystack, static function (Node $node): bool {
                return $node instanceof Node\Expr\FuncCall
                    || $node instanceof Node\Expr\MethodCall
                    || $node instanceof Node\Expr\NullsafeMethodCall
                    || $node instanceof Node\Expr\StaticCall;
            });
            foreach ($calls as $call) {
                if ($this->isInsideOtherFunction($call, $funcs, $scope)) {
                    continue;
                }
                $byCall[spl_object_id($call)] = $names;
            }
        }

        return $byCall;
    }

    /**
     * @param list<Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     */
    private function isInsideAnyFunction(Node $node, array $funcs): bool
    {
        $target = spl_object_id($node);
        foreach ($funcs as $func) {
            $found = $this->finder()->find($func, static function (Node $inner) use ($target): bool {
                return spl_object_id($inner) === $target;
            });
            if ($found !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     */
    private function isInsideOtherFunction(Node $call, array $funcs, Node|null $scope): bool
    {
        foreach ($funcs as $func) {
            if ($scope !== null && $func === $scope) {
                continue;
            }
            $target = spl_object_id($call);
            $found = $this->finder()->find($func, static function (Node $inner) use ($target): bool {
                return spl_object_id($inner) === $target;
            });
            if ($found !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * A $this->property is deploy-time when it has at least one assignment
     * and every assignment is deploy-time.
     *
     * @param array<string, list<Node\Expr>> $origins
     * @param array<string, true> $seen cycle guard
     */
    private function isDeployTimeProperty(string $name, array $origins, array $seen): bool
    {
        if (isset($seen[$name])) {
            return false;
        }
        $seen[$name] = true;

        $rhsList = $origins['this->' . $name] ?? [];
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

        if (
            $expr instanceof Node\Expr\ConstFetch
            || $expr instanceof Node\Expr\ClassConstFetch
            || $expr instanceof Node\Scalar\MagicConst
        ) {
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
            // Pure path/string helpers: the result stays deploy-time when
            // every argument is (dirname/basename/realpath can never yield
            // a remote URL — worst case a local filename).
            if (!in_array($fn, ['trim', 'ltrim', 'rtrim', 'sprintf', 'dirname', 'basename', 'realpath'], true)) {
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
            if ($this->isDirectoryListing($rhs)) {
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

        if ($expr instanceof Node\Scalar\LNumber || $expr instanceof Node\Scalar\DNumber) {
            return true;
        }

        if ($expr instanceof Node\Scalar\MagicConst) {
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
