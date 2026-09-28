<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A01 Broken Access Control.
 *
 * Flags mutating controller methods with no visible authorization check in the
 * method body, constructor, or property — unless the action is protected by an
 * authorization middleware declared in a route file (`Route::middleware(...)`,
 * `->middleware(...)` chains, `Route::group(['middleware' => ...])`).
 * Route files are recognized by a `/routes/` (or `/Routes/`) path segment or a
 * `web.php`/`api.php` basename. Middleware whose name hints at authorization
 * (`auth`, `can:`, `permission`, `role`, `gate`, `admin`, `bouncer`,
 * `checklevel`, `checkLogin`, API-key/token guards like `*.api.key`,
 * `sanctum`, `jwt`, ...) counts
 * as protection; `throttle` and friends do not. `guest*` middleware is
 * intentionally NOT treated as protection (guest = unauthenticated).
 *
 * Two framework idioms are resolved: `Route::controller(X::class)` groups whose
 * actions are bare method-name strings, and `require`/`include` of another route
 * file inside a group closure (the required file inherits the importer's
 * middleware stack and is not parsed as a standalone root).
 *
 * Actions are keyed by fully-qualified `Class@method` (controller references are
 * resolved through the route file's `use` imports), so same-named controllers in
 * different namespaces (e.g. Admin vs Shop API) never share entries. References
 * that cannot be qualified fall back to short-name matching.
 *
 * In-body authorization covers `authorize*()`, `middleware()`, `abort*()`,
 * and exact `can()`/`cannot()` calls (e.g. `$request->user()->can(...)`),
 * credential verification (`$request->authenticate()`, `Auth::attempt()`),
 * capability proofs (`$request->hasValidSignature()`, `hash_equals()`),
 * plus enforcing gate branches (`if (Gate::...->denies(...)) { throw ...; }`
 * — a bare `allows()` without throw/abort still flags).
 */
final class OwaspAccessControlAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_BROKEN_ACCESS_CONTROL';

    private const MUTATING_METHODS = [
        'store', 'update', 'delete', 'destroy', 'restore', 'forceDelete',
    ];

    private const MUTATING_CALLS = ['save', 'delete', 'update', 'create', 'insert', 'upsert', 'destroy'];

    private const ROUTE_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'any'];

    private const RESOURCE_METHODS = ['index', 'create', 'store', 'show', 'edit', 'update', 'destroy'];

    private const API_RESOURCE_METHODS = ['index', 'store', 'show', 'update', 'destroy'];

    /** @var list<string> */
    private readonly array $extraMiddleware;

    /**
     * @param array{extra_middleware?: string|list<string>} $options
     */
    public function __construct(private readonly bool $routeMiddleware = true, array $options = [])
    {
        $raw = $options['extra_middleware'] ?? [];
        if (is_string($raw)) {
            $raw = [$raw];
        }
        $fragments = [];
        foreach ($raw as $fragment) {
            if (!is_string($fragment)) {
                continue;
            }
            $base = strtolower(trim(explode(':', $fragment, 2)[0]));
            if ($base !== '') {
                $fragments[] = $base;
            }
        }
        $this->extraMiddleware = array_values(array_unique($fragments));
    }

    public function analyze(array $files): array
    {
        $routeAuth = $this->routeMiddleware ? $this->buildRouteAuthMap($files) : [];
        $formRequestAuth = $this->buildFormRequestAuthMap($files);

        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $routeAuth, $formRequestAuth) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * FormRequests with a non-trivial authorize() method perform
     * authorization before validation: store(CustomRequest $request) is
     * protected when CustomRequest::authorize() does real checks. A lone
     * `return true;` (or no authorize() at all) means no protection.
     *
     * @param list<string> $files
     * @return array<string, true> lowercased FQCN => authorized
     */
    private function buildFormRequestAuthMap(array $files): array
    {
        $map = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $base = strtolower((string) pathinfo($file, PATHINFO_BASENAME));
            if (!str_ends_with($base, 'request.php')) {
                continue;
            }
            $ast = $this->parse($this->readFile($file));
            if ($ast === null) {
                continue;
            }
            $nodes = $this->nodeList($ast);
            $namespace = $this->namespaceOf($nodes);
            $classes = $this->finder()->findInstanceOf($nodes, Node\Stmt\Class_::class);
            foreach ($classes as $class) {
                if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                    continue;
                }
                $fqn = strtolower($namespace !== null ? $namespace . '\\' . $class->name->toString() : $class->name->toString());
                foreach ($class->stmts as $stmt) {
                    if (
                        $stmt instanceof Node\Stmt\ClassMethod
                        && strtolower($stmt->name->toString()) === 'authorize'
                        && !$this->isTrivialTrueReturn($stmt)
                    ) {
                        $map[$fqn] = true;
                    }
                }
            }
        }

        return $map;
    }

    private function isTrivialTrueReturn(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null || count($method->stmts) !== 1) {
            return false;
        }
        $only = $method->stmts[0];

        return $only instanceof Node\Stmt\Return_
            && $only->expr instanceof Node\Expr\ConstFetch
            && strtolower($only->expr->name->toString()) === 'true';
    }

    /**
     * @param array<string, string> $uses
     * @param array<string, true> $formRequestAuth
     */
    private function hasAuthorizingFormRequest(
        Node\Stmt\ClassMethod $method,
        array $uses,
        ?string $namespace,
        array $formRequestAuth
    ): bool {
        if ($formRequestAuth === []) {
            return false;
        }
        foreach ($method->params as $param) {
            if (!$param->type instanceof Node\Name) {
                continue;
            }
            $resolved = strtolower($this->resolveName($param->type->toString(), $uses, $namespace));
            if (isset($formRequestAuth[$resolved])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, list<bool>> $routeAuth
     * @param array<string, true> $formRequestAuth
     */
    private function analyzeFile(string $file, array $routeAuth, array $formRequestAuth = []): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $nodes = $this->nodeList($ast);
        $issues = [];
        $classes = $this->finder()->findInstanceOf($nodes, Node\Stmt\Class_::class);
        $namespace = $this->namespaceOf($nodes);
        $uses = $this->useMap($nodes);
        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            foreach ($this->analyzeController($class, $file, $routeAuth, $namespace, $uses, $formRequestAuth) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function isControllerClass(Node\Stmt\Class_ $class): bool
    {
        if ($class->name === null || $class->name->toString() === '') {
            return false;
        }

        // Skip abstract base classes and non-controllers.
        if ($class->isAbstract()) {
            return false;
        }

        return str_ends_with($class->name->toString(), 'Controller');
    }

    /**
     * @param array<string, list<bool>> $routeAuth
     * @param array<string, string> $uses
     * @param array<string, true> $formRequestAuth
     * @return Issue[]
     */
    private function analyzeController(
        Node\Stmt\Class_ $class,
        string $file,
        array $routeAuth,
        ?string $namespace,
        array $uses = [],
        array $formRequestAuth = []
    ): array {
        $issues = [];
        $hasAuthContext = $this->classHasAuthContext($class);

        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Node\Stmt\ClassMethod) {
                continue;
            }
            if (!$stmt->isPublic() || $stmt->isMagic()) {
                continue;
            }

            $methodName = $stmt->name->toString();
            if (!$this->isMutatingMethod($stmt)) {
                continue;
            }
            if ($hasAuthContext || $this->methodHasAuth($stmt)) {
                continue;
            }
            if ($this->isRouteProtected($class, $methodName, $routeAuth, $namespace)) {
                continue;
            }
            if ($this->hasAuthorizingFormRequest($stmt, $uses, $namespace, $formRequestAuth)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Mutating method %s() has no visible authorization check.', $methodName),
                $file,
                $stmt->getStartLine(),
                Severity::Error,
                ['method' => $methodName]
            );
        }

        return $issues;
    }

    private function classHasAuthContext(Node\Stmt\Class_ $class): bool
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if (in_array($prop->name->toString(), ['middleware', 'authorize'], true)) {
                        return true;
                    }
                }
            }

            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === '__construct') {
                if ($stmt->stmts !== null && $this->bodyHasAuth($stmt->stmts)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isMutatingMethod(Node\Stmt\ClassMethod $method): bool
    {
        $name = $method->name->toString();
        if (in_array($name, self::MUTATING_METHODS, true)) {
            return true;
        }

        if ($method->stmts === null) {
            return false;
        }

        $calls = $this->finder()->find($method->stmts, function (Node $node): bool {
            if (!$node instanceof Node\Expr\MethodCall) {
                return false;
            }

            return $node->name instanceof Node\Identifier
                && in_array($node->name->toString(), self::MUTATING_CALLS, true);
        });

        return $calls !== [];
    }

    private function methodHasAuth(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null) {
            return false;
        }

        return $this->bodyHasAuth($method->stmts);
    }

    /**
     * @param array<Node\Stmt> $stmts
     */
    private function bodyHasAuth(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            $found = $this->finder()->find($stmt, function (Node $node): bool {
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toString(), ['authorize', 'authorizeResource', 'middleware', 'abort', 'abortIf', 'abortUnless', 'can', 'cannot', 'hasValidSignature'], true)
                ) {
                    return true;
                }

                // Performing authentication IS authorization context:
                // $request->authenticate(), Auth::attempt(...) verify
                // credentials before mutating (login actions).
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['authenticate', 'attempt'], true)
                ) {
                    return true;
                }

                if (
                    $node instanceof Node\Expr\StaticCall
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toString(), ['allow', 'deny', 'authorize', 'abort', 'abortIf', 'abortUnless'], true)
                    && $node->class instanceof Node\Name
                    && ($node->class->toString() === 'Gate' || str_ends_with($node->class->toString(), '\\Gate'))
                ) {
                    return true;
                }

                // Auth::attempt(...) verifies credentials (Bus::attemptBulk
                // dispatches jobs instead — deliberately not covered).
                if (
                    $node instanceof Node\Expr\StaticCall
                    && $node->name instanceof Node\Identifier
                    && strtolower($node->name->toString()) === 'attempt'
                    && $node->class instanceof Node\Name
                    && in_array(strtolower(ltrim($node->class->toString(), '\\')), ['auth', 'authmanager'], true)
                ) {
                    return true;
                }

                if (
                    $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && in_array($node->name->toString(), ['abort', 'abort_if', 'abort_unless', 'hash_equals'], true)
                ) {
                    return true;
                }

                if (
                    ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['hashequals'], true)
                ) {
                    return true;
                }

                return false;
            });

            if ($found !== []) {
                return true;
            }
        }

        return $this->hasEnforcingGateCheck($stmts);
    }

    /**
     * Enforcing gate pattern: if (...->denies(...)/allows(...)) { throw ...; }
     * or { abort(...); }. A bare Gate::allows() without an enforcing branch
     * stays flaggable — the check alone enforces nothing.
     *
     * @param array<Node\Stmt> $stmts
     */
    private function hasEnforcingGateCheck(array $stmts): bool
    {
        $ifs = $this->finder()->find($stmts, static function (Node $node): bool {
            return $node instanceof Node\Stmt\If_;
        });
        foreach ($ifs as $if) {
            if (!$if instanceof Node\Stmt\If_) {
                continue;
            }
            $cond = $this->finder()->find($if->cond, function (Node $node): bool {
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['denies', 'allows', 'authorize', 'can', 'cannot'], true)
                ) {
                    return true;
                }
                if (
                    $node instanceof Node\Expr\StaticCall
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['denies', 'allows'], true)
                ) {
                    return true;
                }

                return false;
            });
            if ($cond === []) {
                continue;
            }
            $enforcing = $this->finder()->find($if->stmts, function (Node $node): bool {
                if ($node instanceof Node\Expr\Throw_) {
                    return true;
                }
                if (
                    $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && in_array($node->name->toString(), ['abort', 'abort_if', 'abort_unless'], true)
                ) {
                    return true;
                }
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toString(), ['abort', 'abortIf', 'abortUnless'], true)
                ) {
                    return true;
                }

                return false;
            });
            if ($enforcing !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, list<bool>> $routeAuth
     */
    private function isRouteProtected(
        Node\Stmt\Class_ $class,
        string $method,
        array $routeAuth,
        ?string $namespace
    ): bool {
        if ($class->name === null) {
            return false;
        }

        $short = $class->name->toString();
        $fqn = $namespace !== null ? $namespace . '\\' . $short : $short;

        $fqnEntries = $routeAuth[strtolower($fqn . '@' . $method)] ?? [];
        if ($fqnEntries !== []) {
            return $this->allProtected($fqnEntries);
        }

        $shortEntries = $routeAuth[strtolower($short . '@' . $method)] ?? [];

        return $shortEntries !== [] && $this->allProtected($shortEntries);
    }

    /**
     * @param list<bool> $entries
     */
    private function allProtected(array $entries): bool
    {
        foreach ($entries as $protected) {
            if (!$protected) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<string> $files
     * @return array<string, list<bool>> action key => per-route auth flags
     */
    private function buildRouteAuthMap(array $files): array
    {
        $routeFiles = [];
        $providerFiles = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isRouteFile($file)) {
                $routeFiles[] = $file;
            } elseif (str_ends_with(strtolower(str_replace('\\', '/', $file)), 'serviceprovider.php')) {
                $providerFiles[] = $file;
            }
        }

        // Files pulled in via require/include inherit the importer's middleware
        // stack, so they are parsed through the importer — not as standalone roots
        // (a root parse would record phantom unprotected entries).
        $included = [];
        foreach (array_merge($routeFiles, $providerFiles) as $file) {
            $ast = $this->parse($this->readFile($file));
            if ($ast === null) {
                continue;
            }
            foreach ($this->collectRequiredFiles($this->nodeList($ast), dirname($file)) as $required) {
                $included[$required] = true;
            }
        }

        $map = [];
        foreach ($routeFiles as $file) {
            $real = function_exists('realpath') ? (realpath($file) ?: $file) : $file;
            if (isset($included[$real])) {
                continue;
            }
            $ast = $this->parse($this->readFile($file));
            if ($ast === null) {
                continue;
            }
            $visited = [$real => true];
            $nodes = $this->nodeList($ast);
            $this->collectRouteAuth($nodes, [], $map, $file, $visited, null, $this->useMap($nodes), $this->namespaceOf($nodes));
        }

        // RouteServiceProvider-style loading: Route::group(['middleware' =>
        // ...], fn () => require base_path('routes/api.php')). Only group
        // calls are processed as roots — inner verbs are reached through the
        // group recursion with the provider's middleware stack, so processing
        // them here as well would record phantom unprotected entries.
        foreach ($providerFiles as $file) {
            $ast = $this->parse($this->readFile($file));
            if ($ast === null) {
                continue;
            }
            $nodes = $this->nodeList($ast);
            $real = function_exists('realpath') ? (realpath($file) ?: $file) : $file;
            $visited = [$real => true];
            $uses = $this->useMap($nodes);
            $namespace = $this->namespaceOf($nodes);
            $calls = $this->finder()->find($nodes, static function (Node $node): bool {
                return $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall;
            });
            // Calls nested inside a Route::group closure are reached through
            // the group recursion with the provider's middleware stack —
            // processing them here as well would record phantom unprotected
            // entries, so only outermost calls are processed as roots.
            $nested = [];
            foreach ($calls as $call) {
                if (
                    ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)
                    && $this->isRouteGroupCall($call)
                ) {
                    // All calls inside the group closure are reached through
                    // the group recursion — never process them as roots.
                    $inners = $this->finder()->find($call->args, static function (Node $node): bool {
                        return $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall;
                    });
                    foreach ($inners as $inner) {
                        $nested[spl_object_id($inner)] = true;
                    }
                }
            }
            foreach ($calls as $call) {
                if (!($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)) {
                    continue;
                }
                if (isset($nested[spl_object_id($call)])) {
                    continue;
                }
                $this->processRouteCall($call, [], $map, $file, $visited, null, $uses, $namespace);
            }
        }

        return $map;
    }

    /**
     * A Route::group(...) call (terminal static or chained
     * Route::middleware(...)->group(...)).
     */
    private function isRouteGroupCall(Node\Expr $node): bool
    {
        $current = $node;
        $sawGroup = $current instanceof Node\Expr\StaticCall
            && $current->name instanceof Node\Identifier
            && strtolower($current->name->toString()) === 'group';
        while ($current instanceof Node\Expr\MethodCall) {
            if (
                $current->name instanceof Node\Identifier
                && strtolower($current->name->toString()) === 'group'
            ) {
                $sawGroup = true;
            }
            $current = $current->var;
        }

        return $sawGroup
            && $current instanceof Node\Expr\StaticCall
            && $current->class instanceof Node\Name
            && $this->shortClass($current->class->toString()) === 'Route';
    }

    /**
     * @param array<array-key, mixed> $ast
     * @return list<Node>
     */
    private function nodeList(array $ast): array
    {
        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    private function isRouteFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);
        if (str_contains($normalized, '/routes/') || str_contains($normalized, '/Routes/')) {
            return true;
        }

        $base = strtolower((string) pathinfo($normalized, PATHINFO_BASENAME));

        return $base === 'web.php' || $base === 'api.php';
    }

    /**
     * @param array<int, Node> $stmts
     * @param list<string> $stack
     * @param array<string, list<bool>> $map
     * @param array<string, true> $visited
     * @param array<string, string> $uses
     */
    private function collectRouteAuth(
        array $stmts,
        array $stack,
        array &$map,
        string $file,
        array &$visited,
        ?string $controller = null,
        array $uses = [],
        ?string $namespace = null
    ): void {
        foreach ($stmts as $stmt) {
            $expr = $stmt instanceof Node\Stmt\Expression ? $stmt->expr : null;
            if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
                $this->processRouteCall($expr, $stack, $map, $file, $visited, $controller, $uses, $namespace);
            } elseif ($expr instanceof Node\Expr\Include_) {
                $this->collectRequiredRouteFile($expr, $stack, $map, $file, $visited, $controller);
            } else {
                // Route groups nested in top-level guards (installer checks,
                // maintenance mode, feature flags) inherit the ambient stack.
                foreach ($this->blockChildLists($stmt) as $child) {
                    $this->collectRouteAuth($child, $stack, $map, $file, $visited, $controller, $uses, $namespace);
                }
            }
        }
    }

    /**
     * Statement lists nested in block statements (if/try/loops) — same
     * middleware stack as the enclosing scope.
     *
     * @return list<array<int, Node>>
     */
    private function blockChildLists(Node $stmt): array
    {
        $out = [];
        if ($stmt instanceof Node\Stmt\If_) {
            $out[] = $stmt->stmts;
            foreach ($stmt->elseifs as $elseif) {
                $out[] = $elseif->stmts;
            }
            if ($stmt->else instanceof Node\Stmt\Else_) {
                $out[] = $stmt->else->stmts;
            }

            return $out;
        }
        if ($stmt instanceof Node\Stmt\TryCatch) {
            $out[] = $stmt->stmts;
            foreach ($stmt->catches as $catch) {
                $out[] = $catch->stmts;
            }
            if ($stmt->finally instanceof Node\Stmt\Finally_) {
                $out[] = $stmt->finally->stmts;
            }

            return $out;
        }
        if (
            $stmt instanceof Node\Stmt\Foreach_
            || $stmt instanceof Node\Stmt\For_
            || $stmt instanceof Node\Stmt\While_
            || $stmt instanceof Node\Stmt\Do_
        ) {
            $out[] = $stmt->stmts;

            return $out;
        }

        return $out;
    }

    /**
     * @param list<string> $stack
     * @param array<string, list<bool>> $map
     * @param array<string, true> $visited
     */
    private function collectRequiredRouteFile(
        Node\Expr\Include_ $include,
        array $stack,
        array &$map,
        string $file,
        array &$visited,
        ?string $controller = null
    ): void {
        $path = $this->includePath($include, dirname($file));
        if ($path === null || isset($visited[$path])) {
            return;
        }
        $visited[$path] = true;
        $code = $this->readFile($path);
        if ($code === '') {
            return;
        }
        $ast = $this->parse($code);
        if ($ast === null) {
            return;
        }
        $nodes = $this->nodeList($ast);
        $this->collectRouteAuth($nodes, $stack, $map, $path, $visited, $controller, $this->useMap($nodes), $this->namespaceOf($nodes));
    }

    /**
     * @param list<Node> $ast
     * @return list<string> realpaths of relatively-required files
     */
    private function collectRequiredFiles(array $ast, string $dir): array
    {
        $out = [];
        $includes = $this->finder()->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\Include_;
        });
        foreach ($includes as $include) {
            if (!$include instanceof Node\Expr\Include_) {
                continue;
            }
            $path = $this->includePath($include, $dir);
            if ($path !== null) {
                $out[] = $path;
            }
        }

        return $out;
    }

    private function includePath(Node\Expr\Include_ $include, string $dir): ?string
    {
        $target = $this->includeTarget($include);
        if ($target === null) {
            return null;
        }
        // Plain relative require: resolve against the including file's dir.
        $candidate = $dir . DIRECTORY_SEPARATOR . $target;
        if (is_file($candidate)) {
            $real = realpath($candidate);

            return $real === false ? null : $real;
        }
        // base_path('routes/api.php') inside a RouteServiceProvider group:
        // walk up from the including file until the project-root-relative
        // path exists (…/app/Providers → …/routes/api.php).
        $relative = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $target), DIRECTORY_SEPARATOR);
        $probe = $dir;
        for ($depth = 0; $depth < 8; $depth++) {
            $candidate = $probe . DIRECTORY_SEPARATOR . $relative;
            if (is_file($candidate)) {
                $real = realpath($candidate);

                return $real === false ? null : $real;
            }
            $parent = dirname($probe);
            if ($parent === $probe) {
                break;
            }
            $probe = $parent;
        }

        return null;
    }

    /**
     * A require/include target: a string literal, or a single-argument
     * base_path()/app_path()/database_path()/etc. helper call.
     */
    private function includeTarget(Node\Expr\Include_ $include): ?string
    {
        if ($include->expr instanceof Node\Scalar\String_) {
            return $include->expr->value === '' ? null : $include->expr->value;
        }

        if (
            $include->expr instanceof Node\Expr\FuncCall
            && $include->expr->name instanceof Node\Name
            && in_array(strtolower($include->expr->name->toString()), ['base_path', 'app_path', 'database_path', 'resource_path', 'config_path', 'lang_path', 'public_path', 'storage_path'], true)
        ) {
            $arg = $include->expr->args[0] ?? null;
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_ && $arg->value->value !== '') {
                return $arg->value->value;
            }
        }

        return null;
    }

    /**
     * @param list<string> $stack
     * @param array<string, list<bool>> $map
     * @param array<string, true> $visited
     * @param array<string, string> $uses
     */
    private function processRouteCall(
        Node\Expr $node,
        array $stack,
        array &$map,
        string $file,
        array &$visited,
        ?string $controller = null,
        array $uses = [],
        ?string $namespace = null
    ): void {
        // Outermost call wins: `Route::get(...)->middleware(...)` stores the
        // action args on the terminal StaticCall, `Route::middleware(...)->get(...)`
        // on the MethodCall — track both.
        /** @var array<string, Node\Expr\MethodCall> $chain */
        $chain = [];
        $current = $node;
        while ($current instanceof Node\Expr\MethodCall) {
            if ($current->name instanceof Node\Identifier) {
                $name = strtolower($current->name->toString());
                if (!isset($chain[$name])) {
                    $chain[$name] = $current;
                }
            }
            $current = $current->var;
        }

        if (!$current instanceof Node\Expr\StaticCall || !$current->class instanceof Node\Name) {
            return;
        }
        if ($this->shortClass($current->class->toString()) !== 'Route') {
            return;
        }
        if (!$current->name instanceof Node\Identifier) {
            return;
        }

        $middlewares = $stack;
        if (isset($chain['middleware'])) {
            foreach ($chain['middleware']->args as $arg) {
                if ($arg instanceof Node\Arg) {
                    $middlewares = array_merge($middlewares, $this->middlewareStrings($arg->value));
                }
            }
        }
        $terminal = strtolower($current->name->toString());
        if ($terminal === 'middleware') {
            foreach ($current->args as $arg) {
                if ($arg instanceof Node\Arg) {
                    $middlewares = array_merge($middlewares, $this->middlewareStrings($arg->value));
                }
            }
        }

        // `Route::controller(X::class)->...->group(...)`: the controller is the
        // terminal static call, not a chain link.
        if ($terminal === 'controller') {
            $ctrlArg = $current->args[0] ?? null;
            if ($ctrlArg instanceof Node\Arg) {
                $controller = $this->classItemName($ctrlArg->value, $uses, $namespace) ?? $controller;
            }
        }

        if (isset($chain['group'])) {
            $this->processGroupArgs(
                $chain['group']->args,
                $middlewares,
                $map,
                $file,
                $visited,
                $this->chainController($chain, $uses, $namespace) ?? $controller,
                $uses,
                $namespace
            );

            return;
        }

        if ($terminal === 'group') {
            $this->processGroupArgs($current->args, $middlewares, $map, $file, $visited, $controller, $uses, $namespace);

            return;
        }

        $verbNode = null;
        $verb = null;
        foreach (array_merge(['match', 'resource', 'apiresource'], self::ROUTE_VERBS) as $candidate) {
            if (isset($chain[$candidate])) {
                $verb = $candidate;
                $verbNode = $chain[$candidate];
                break;
            }
        }
        if ($verbNode === null) {
            if (!in_array($terminal, array_merge(['match', 'resource', 'apiresource'], self::ROUTE_VERBS), true)) {
                return;
            }
            $verb = $terminal;
            $verbNode = $current;
        }

        if ($verb === 'resource' || $verb === 'apiresource') {
            $this->recordResource($verbNode, $middlewares, $map, $verb === 'apiresource', $uses, $namespace);

            return;
        }

        $actionArg = $verb === 'match' ? ($verbNode->args[2] ?? null) : ($verbNode->args[1] ?? null);
        if (!$actionArg instanceof Node\Arg) {
            return;
        }

        foreach ($this->actionKeys($actionArg->value, $this->chainController($chain, $uses, $namespace) ?? $controller, $uses, $namespace) as $key) {
            $map[$key][] = $this->hasAuthMiddleware($middlewares);
        }
    }

    /**
     * @param array<string, Node\Expr\MethodCall> $chain
     * @param array<string, string> $uses
     */
    private function chainController(array $chain, array $uses, ?string $namespace): ?string
    {
        if (!isset($chain['controller'])) {
            return null;
        }
        $arg = $chain['controller']->args[0] ?? null;
        if (!$arg instanceof Node\Arg) {
            return null;
        }

        return $this->classItemName($arg->value, $uses, $namespace);
    }

    /**
     * @param array<int, Node\Arg|Node\VariadicPlaceholder> $args
     * @param list<string> $middlewares
     * @param array<string, list<bool>> $map
     * @param array<string, true> $visited
     * @param array<string, string> $uses
     */
    private function processGroupArgs(
        array $args,
        array $middlewares,
        array &$map,
        string $file,
        array &$visited,
        ?string $controller = null,
        array $uses = [],
        ?string $namespace = null
    ): void {
        $extended = $middlewares;
        $first = $args[0] ?? null;
        $second = $args[1] ?? null;
        if ($first instanceof Node\Arg && $first->value instanceof Node\Expr\Array_) {
            $extended = array_merge($extended, $this->groupArrayMiddleware($first->value));
        }
        $closure = $second instanceof Node\Arg ? $second->value : ($first instanceof Node\Arg ? $first->value : null);
        if ($closure instanceof Node\Expr\Closure && is_array($closure->stmts)) {
            $this->collectRouteAuth($closure->stmts, $extended, $map, $file, $visited, $controller, $uses, $namespace);
        }
    }

    /**
     * @return list<string>
     */
    private function groupArrayMiddleware(Node\Expr\Array_ $config): array
    {
        $out = [];
        foreach ($config->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                continue;
            }
            if ($item->key->value !== 'middleware') {
                continue;
            }
            $out = array_merge($out, $this->middlewareStrings($item->value));
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private function middlewareStrings(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Scalar\String_) {
            return [$expr->value];
        }

        if ($expr instanceof Node\Expr\Array_) {
            $out = [];
            foreach ($expr->items as $item) {
                if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                    $out[] = $item->value->value;
                }
            }

            return $out;
        }

        return [];
    }

    /**
     * @param array<string, string> $uses
     * @return list<string>
     */
    private function actionKeys(Node\Expr $expr, ?string $controller = null, array $uses = [], ?string $namespace = null): array
    {
        if ($expr instanceof Node\Scalar\String_) {
            if (str_contains($expr->value, '@')) {
                [$class, $method] = explode('@', $expr->value, 2);

                return [$this->actionKey($class, $method, $uses, $namespace)];
            }
            if ($controller !== null && $expr->value !== '') {
                return [strtolower($controller . '@' . $expr->value)];
            }

            return [];
        }

        if ($expr instanceof Node\Expr\Array_) {
            if (
                isset($expr->items[0], $expr->items[1])
                && $expr->items[0] instanceof Node\Expr\ArrayItem
                && $expr->items[1] instanceof Node\Expr\ArrayItem
                && $expr->items[0]->key === null
                && $expr->items[1]->key === null
            ) {
                $classItem = $expr->items[0];
                $methodItem = $expr->items[1];
                if (
                    !$methodItem->value instanceof Node\Scalar\String_
                ) {
                    return [];
                }
                $class = $this->classItemName($classItem->value, $uses, $namespace);
                if ($class === null) {
                    return [];
                }

                return [strtolower($class . '@' . $methodItem->value->value)];
            }

            // Legacy array syntax: ['as' => ..., 'uses' => 'FQCN@method'].
            foreach ($expr->items as $item) {
                if (
                    $item instanceof Node\Expr\ArrayItem
                    && $item->key instanceof Node\Scalar\String_
                    && $item->key->value === 'uses'
                ) {
                    return $this->actionKeys($item->value, $controller, $uses, $namespace);
                }
            }

            return [];
        }

        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            $class = $this->resolveName($expr->class->toString(), $uses, $namespace);

            return [strtolower($class . '@__invoke')];
        }

        return [];
    }

    /**
     * @param array<string, string> $uses
     */
    private function actionKey(string $class, string $method, array $uses, ?string $namespace): string
    {
        $trimmed = trim($class);
        if ($trimmed === '') {
            return strtolower('@' . trim($method));
        }

        return strtolower($this->resolveName($trimmed, $uses, $namespace) . '@' . trim($method));
    }

    /**
     * @param array<string, string> $uses
     */
    private function classItemName(Node\Expr $expr, array $uses, ?string $namespace): ?string
    {
        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            return $this->resolveName($expr->class->toString(), $uses, $namespace);
        }

        if ($expr instanceof Node\Scalar\String_ && $expr->value !== '') {
            return $this->resolveName($expr->value, $uses, $namespace);
        }

        return null;
    }

    /**
     * Resolve a class reference against the file's imports (alias => FQCN).
     *
     * @param array<string, string> $uses
     */
    private function resolveName(string $name, array $uses, ?string $namespace): string
    {
        if (str_starts_with($name, '\\')) {
            return ltrim($name, '\\');
        }

        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            $rest = substr($name, $pos);
            if (isset($uses[$first])) {
                return $uses[$first] . $rest;
            }

            return $namespace !== null ? $namespace . '\\' . $name : $name;
        }

        $lower = strtolower($name);
        if (isset($uses[$lower])) {
            return $uses[$lower];
        }

        return $namespace !== null ? $namespace . '\\' . $name : $name;
    }

    /**
     * @param list<Node> $nodes
     * @return array<string, string> lowercase alias => FQCN
     */
    private function useMap(array $nodes): array
    {
        $map = [];
        $imports = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Use_ || $node instanceof Node\Stmt\GroupUse;
        });

        foreach ($imports as $import) {
            if ($import instanceof Node\Stmt\GroupUse) {
                foreach ($import->uses as $use) {
                    if (!$use instanceof Node\Stmt\UseUse) {
                        continue;
                    }
                    $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                    $map[strtolower($alias)] = $import->prefix->toString() . '\\' . $use->name->toString();
                }
                continue;
            }

            if (!$import instanceof Node\Stmt\Use_ || $import->type !== Node\Stmt\Use_::TYPE_NORMAL) {
                continue;
            }

            foreach ($import->uses as $use) {
                if (!$use instanceof Node\Stmt\UseUse) {
                    continue;
                }
                $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                $map[strtolower($alias)] = $use->name->toString();
            }
        }

        return $map;
    }

    /**
     * @param list<Node> $nodes
     */
    private function namespaceOf(array $nodes): ?string
    {
        $found = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Namespace_;
        });

        foreach ($found as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }

    /**
     * @param list<string> $middlewares
     * @param array<string, list<bool>> $map
     * @param array<string, string> $uses
     */
    private function recordResource(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        array $middlewares,
        array &$map,
        bool $api,
        array $uses,
        ?string $namespace
    ): void {
        $controllerArg = $call->args[1] ?? null;
        if (!$controllerArg instanceof Node\Arg) {
            return;
        }
        $controller = $this->classItemName($controllerArg->value, $uses, $namespace);
        if ($controller === null) {
            return;
        }

        $protected = $this->hasAuthMiddleware($middlewares);
        foreach ($api ? self::API_RESOURCE_METHODS : self::RESOURCE_METHODS as $method) {
            $map[strtolower($controller . '@' . $method)][] = $protected;
        }
    }

    /**
     * @param list<string> $middlewares
     */
    private function hasAuthMiddleware(array $middlewares): bool
    {
        foreach ($middlewares as $middleware) {
            if ($this->isAuthMiddleware($middleware)) {
                return true;
            }
        }

        return false;
    }

    private function isAuthMiddleware(string $middleware): bool
    {
        $parts = explode(':', $middleware, 2);
        $base = strtolower(trim($parts[0]));
        if ($base === '') {
            return false;
        }
        // Guest middleware redirects authenticated users away — it marks a
        // route as public, never as protected (even `guestAdmin` which
        // contains the `admin` hint).
        if ($base === 'guest' || str_starts_with($base, 'guest')) {
            return false;
        }
        if (in_array($base, ['auth', 'verified', 'signed', 'can'], true)) {
            return true;
        }

        foreach ($this->extraMiddleware as $fragment) {
            if (str_contains($base, $fragment)) {
                return true;
            }
        }

        foreach (['can', 'auth', 'permission', 'role', 'gate', 'admin', 'bouncer', 'checklevel', 'login', 'apikey', 'api_key', 'api.key', 'sanctum', 'jwt', 'oauth'] as $hint) {
            if (str_contains($base, $hint)) {
                return true;
            }
        }

        return false;
    }

    private function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
