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
 * (`auth`, `can:`, `permission`, `role`, `gate`, `admin`, `bouncer`, ...) counts
 * as protection; `throttle` and friends do not.
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

    public function __construct(private readonly bool $routeMiddleware = true)
    {
    }

    public function analyze(array $files): array
    {
        $routeAuth = $this->routeMiddleware ? $this->buildRouteAuthMap($files) : [];

        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $routeAuth) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @param array<string, list<bool>> $routeAuth
     */
    private function analyzeFile(string $file, array $routeAuth): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $nodes = $this->nodeList($ast);
        $issues = [];
        $classes = $this->finder()->findInstanceOf($nodes, Node\Stmt\Class_::class);
        $namespace = $this->namespaceOf($nodes);
        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            foreach ($this->analyzeController($class, $file, $routeAuth, $namespace) as $issue) {
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
     * @return Issue[]
     */
    private function analyzeController(
        Node\Stmt\Class_ $class,
        string $file,
        array $routeAuth,
        ?string $namespace
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
                    && in_array($node->name->toString(), ['authorize', 'authorizeResource', 'middleware', 'abort', 'abortIf', 'abortUnless'], true)
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

                if (
                    $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && in_array($node->name->toString(), ['abort', 'abort_if', 'abort_unless'], true)
                ) {
                    return true;
                }

                return false;
            });

            if ($found !== []) {
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
        foreach ($files as $file) {
            if ($this->supports($file) && $this->isRouteFile($file)) {
                $routeFiles[] = $file;
            }
        }

        // Files pulled in via require/include inherit the importer's middleware
        // stack, so they are parsed through the importer — not as standalone roots
        // (a root parse would record phantom unprotected entries).
        $included = [];
        foreach ($routeFiles as $file) {
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

        return $map;
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
            }
        }
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
        if (!$include->expr instanceof Node\Scalar\String_) {
            return null;
        }
        $target = $include->expr->value;
        if ($target === '') {
            return null;
        }
        $candidate = $dir . DIRECTORY_SEPARATOR . $target;
        if (!is_file($candidate)) {
            return null;
        }
        $real = realpath($candidate);

        return $real === false ? null : $real;
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

        if ($expr instanceof Node\Expr\Array_ && isset($expr->items[0], $expr->items[1])) {
            $classItem = $expr->items[0];
            $methodItem = $expr->items[1];
            if (
                !$classItem instanceof Node\Expr\ArrayItem
                || !$methodItem instanceof Node\Expr\ArrayItem
                || !$methodItem->value instanceof Node\Scalar\String_
            ) {
                return [];
            }
            $class = $this->classItemName($classItem->value, $uses, $namespace);
            if ($class === null) {
                return [];
            }

            return [strtolower($class . '@' . $methodItem->value->value)];
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
        if (in_array($base, ['auth', 'verified', 'signed', 'can'], true)) {
            return true;
        }

        foreach (['can', 'auth', 'permission', 'role', 'gate', 'admin', 'bouncer', 'checklevel'] as $hint) {
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
