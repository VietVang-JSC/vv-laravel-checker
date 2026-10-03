<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Analysis\ConstantScope;
use Rampart\QualityChecker\Analysis\ConstantValue;
use Rampart\QualityChecker\Analysis\ConstantValueResolver;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Scanning\ScanContext;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Laravel semantic index: Route → Controller resolution.
 *
 * Parses route files (plus RouteServiceProvider-style loaders) into
 * RouteNode entries: which controller action answers which HTTP method(s)
 * at which URI, under which middleware stack, declared where. Unknown
 * stays unknown — dynamic URIs/actions resolve to null, never a guess.
 *
 * Supported route DSL (deliberately not 100% of Laravel):
 * get/post/put/patch/delete/options/match/any, controller(), resource()/
 * apiResource() (with only/except), middleware()/group() chains and array
 * groups (incl. nested), prefix(), require/include of route files
 * (string paths and base_path()/app_path()/... helpers), provider-wrapped
 * loading, and top-level if/try/loop guards. Legacy 'Class@method' and
 * [Class::class, 'method'] actions with FQCN resolution via use imports.
 *
 * v0.3.1 covers Route → Controller → Middleware. FormRequest/Policy/Gate
 * evidence aggregation lands in v0.3.2/v0.3.3 on top of this graph.
 */
final class LaravelSemanticIndex implements ScanContextAware
{
    use ScanContextTrait;

    private const ROUTE_VERBS = [
        'get', 'post', 'put', 'patch', 'delete', 'options',
        'match', 'any', 'resource', 'apiresource',
    ];

    private const ALL_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options'];

    private const RESOURCE_METHODS = [
        'index' => ['get', ''],
        'create' => ['get', '/create'],
        'store' => ['post', ''],
        'show' => ['get', '/{id}'],
        'edit' => ['get', '/{id}/edit'],
        'update' => ['put', '/{id}'],
        'destroy' => ['delete', '/{id}'],
    ];

    private const API_RESOURCE_METHODS = ['index', 'store', 'show', 'update', 'destroy'];

    /** @var list<RouteNode> */
    private array $routes = [];

    /** @var array<string, true> visited realpaths */
    private array $visited = [];

    /** @var array<string, ConstantScope> file => scope */
    private array $constScopes = [];

    private ConstantValueResolver $constants;

    private NodeFinder $finder;

    private int $declarations = 0;

    private int $resolvedNodes = 0;

    private int $fullNodes = 0;

    private int $unknownNodes = 0;

    /** @var array<string, int> */
    private array $unknownReasons = [];

    private ?string $lastUnresolvedReason = null;

    public function __construct(?ScanContext $scan = null)
    {
        if ($scan !== null) {
            $this->setScanContext($scan);
        }
        $this->finder = new CountingNodeFinder();
        $this->constants = new ConstantValueResolver();
    }

    /**
     * Semantic coverage: how many route declarations resolved fully,
     * partially (known action, dynamic URI) or not at all — and why.
     *
     * @return array{total: int, resolved: int, full: int, partial: int, unknown: int, reasons: array<string, int>}
     */
    public function coverage(): array
    {
        return [
            'total' => $this->declarations,
            'resolved' => $this->resolvedNodes,
            'full' => $this->fullNodes,
            'partial' => $this->resolvedNodes - $this->fullNodes,
            'unknown' => $this->unknownNodes,
            'reasons' => $this->unknownReasons,
        ];
    }

    private function finder(): NodeFinder
    {
        return $this->finder;
    }

    private function scopeFor(string $file): ConstantScope
    {
        if (!isset($this->constScopes[$file])) {
            $nodes = $this->sharedAst($file) ?? [];
            $this->constScopes[$file] = ConstantScope::forFile($nodes, $file);
        }

        return $this->constScopes[$file];
    }

    /**
     * Proven-constant string for an expression, or null when unproven.
     * Plain literals short-circuit without scope work.
     */
    private function resolveConstant(Node\Expr $expr, string $file, int $line): ?ConstantValue
    {
        if ($expr instanceof Node\Scalar\String_) {
            return new ConstantValue($expr->value, 'exact', [[
                'kind' => 'literal',
                'detail' => $expr->value,
                'file' => $file,
                'line' => $expr->getStartLine(),
            ]]);
        }
        $scope = $this->scopeFor($file)->forNode($expr);
        $value = $this->constants->resolve($expr, $scope, $line);
        if ($value === null) {
            $this->lastUnresolvedReason = $this->reasonBucket($expr);
        }

        return $value;
    }

    /**
     * Map resolver diagnostics to coverage buckets: dynamic-variable,
     * function-call, conditional-assignment, unsupported-expression,
     * unresolved-include.
     */
    private function reasonBucket(Node\Expr $expr): string
    {
        $reason = $this->constants->failureReason();
        if ($reason === 'conditional-assignment') {
            return 'conditional-assignment';
        }
        if ($reason === 'function-call') {
            return 'function-call';
        }
        if (
            in_array($reason, [
            'unassigned-variable', 'ambiguous-assignment', 'use-before-assign',
            'cyclic-assignment', 'depth-exceeded', 'dynamic-concat', 'dynamic-variable',
            ], true)
        ) {
            return 'dynamic-variable';
        }
        if ($expr instanceof Node\Expr\FuncCall) {
            return 'function-call';
        }
        if ($expr instanceof Node\Expr\Variable) {
            return 'dynamic-variable';
        }

        return 'unsupported-expression';
    }

    /**
     * @param list<string> $files absolute paths
     */
    public function build(array $files): self
    {
        $routeFiles = [];
        $providerFiles = [];
        foreach ($files as $file) {
            if (strtolower((string) pathinfo($file, PATHINFO_EXTENSION)) !== 'php') {
                continue;
            }
            if (PhpNameResolver::isRouteFile($file)) {
                $routeFiles[] = $file;
                continue;
            }
            if (str_ends_with(strtolower(str_replace('\\', '/', $file)), 'serviceprovider.php')) {
                $providerFiles[] = $file;
            }
        }

        // Files pulled in via require/include are parsed through the
        // importer with its stack — never as standalone roots.
        $included = [];
        foreach (array_merge($routeFiles, $providerFiles) as $file) {
            $nodes = $this->nodesOf($file);
            if ($nodes === null) {
                continue;
            }
            foreach ($this->collectRequiredFiles($nodes, dirname($file), $file) as $required) {
                $included[$required] = true;
            }
        }

        foreach ($routeFiles as $file) {
            $real = realpath($file) ?: $file;
            if (isset($included[$real]) || isset($this->visited[$real])) {
                continue;
            }
            $this->visited[$real] = true;
            $nodes = $this->nodesOf($file);
            if ($nodes === null) {
                continue;
            }
            $this->walkStmts($nodes, $this->baseStack(), $file, PhpNameResolver::useMap($nodes, $this->finder), PhpNameResolver::namespaceOf($nodes, $this->finder));
        }

        foreach ($providerFiles as $file) {
            $nodes = $this->nodesOf($file);
            if ($nodes === null) {
                continue;
            }
            $uses = PhpNameResolver::useMap($nodes, $this->finder);
            $namespace = PhpNameResolver::namespaceOf($nodes, $this->finder);
            $calls = $this->finder->find($nodes, static function (Node $node): bool {
                return $node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall;
            });
            $nested = [];
            foreach ($calls as $call) {
                if ($this->isRouteGroupCall($call)) {
                    foreach ($this->callsInArgs($call) as $inner) {
                        $nested[spl_object_id($inner)] = true;
                    }
                }
            }
            foreach ($calls as $call) {
                if (
                    ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)
                    && !isset($nested[spl_object_id($call)])
                ) {
                    $this->processCall($call, $this->baseStack(), $file, $uses, $namespace);
                }
            }
        }

        return $this;
    }

    /**
     * @return list<RouteNode>
     */
    public function routes(): array
    {
        return $this->routes;
    }

    /**
     * Routes answering a controller action (FQCN preferred, short-name
     * fallback for unqualified references).
     *
     * @return list<RouteNode>
     */
    public function routesForAction(string $class, string $method): array
    {
        $method = strtolower($method);
        $fqn = strtolower(ltrim($class, '\\'));
        $short = strtolower(PhpNameResolver::shortClass($class));

        $fqnHits = [];
        $shortHits = [];
        foreach ($this->routes as $route) {
            if ($route->controller === null || strtolower($route->action ?? '') !== $method) {
                continue;
            }
            $routeClass = strtolower(ltrim($route->controller, '\\'));
            if ($routeClass === $fqn) {
                $fqnHits[] = $route;
                continue;
            }
            if (PhpNameResolver::shortClass($route->controller) === $short || strtolower($route->controller) === $short) {
                $shortHits[] = $route;
            }
        }

        return $fqnHits !== [] ? $fqnHits : $shortHits;
    }

    /**
     * Merged middleware across all routes answering an action.
     *
     * @return list<string>
     */
    public function middlewareForAction(string $class, string $method): array
    {
        $out = [];
        foreach ($this->routesForAction($class, $method) as $route) {
            foreach ($route->middleware as $middleware) {
                $out[$middleware] = true;
            }
        }

        return array_keys($out);
    }

    /**
     * @return array{middleware: list<string>, prefix: string, controller: string|null}
     */
    private function baseStack(): array
    {
        return ['middleware' => [], 'prefix' => '', 'controller' => null];
    }

    /**
     * @return list<Node>|null
     */
    private function nodesOf(string $file): ?array
    {
        $ast = $this->sharedAst($file);

        return $ast === null || $ast === [] ? null : $ast;
    }

    /**
     * @param list<Node> $stmts
     * @param array{middleware: list<string>, prefix: string, controller: string|null} $stack
     * @param array<string, string> $uses
     */
    private function walkStmts(array $stmts, array $stack, string $file, array $uses, ?string $namespace): void
    {
        foreach ($stmts as $stmt) {
            $expr = $stmt instanceof Node\Stmt\Expression ? $stmt->expr : null;
            if ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
                $this->processCall($expr, $stack, $file, $uses, $namespace);
                continue;
            }
            if ($expr instanceof Node\Expr\Include_) {
                $this->collectRequiredRouteFile($expr, $stack, $file, $uses, $namespace);
                continue;
            }
            foreach ($this->blockChildLists($stmt) as $child) {
                $this->walkStmts($child, $stack, $file, $uses, $namespace);
            }
        }
    }

    /**
     * @return list<array<int, Node>>
     */
    private function blockChildLists(Node $stmt): array
    {
        $out = [];
        if ($stmt instanceof Node\Stmt\If_) {
            if ($stmt->stmts !== []) {
                $out[] = $stmt->stmts;
            }
            foreach ($stmt->elseifs as $elseif) {
                if ($elseif->stmts !== []) {
                    $out[] = $elseif->stmts;
                }
            }
            if ($stmt->else instanceof Node\Stmt\Else_ && $stmt->else->stmts !== []) {
                $out[] = $stmt->else->stmts;
            }

            return $out;
        }
        if ($stmt instanceof Node\Stmt\TryCatch) {
            if ($stmt->stmts !== []) {
                $out[] = $stmt->stmts;
            }
            foreach ($stmt->catches as $catch) {
                if ($catch->stmts !== []) {
                    $out[] = $catch->stmts;
                }
            }
            if ($stmt->finally instanceof Node\Stmt\Finally_ && $stmt->finally->stmts !== []) {
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
            if ($stmt->stmts !== []) {
                $out[] = $stmt->stmts;
            }

            return $out;
        }

        return $out;
    }

    /**
     * @param array{middleware: list<string>, prefix: string, controller: string|null} $stack
     * @param array<string, string> $uses
     */
    private function processCall(Node\Expr $node, array $stack, string $file, array $uses, ?string $namespace): void
    {
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
        if (PhpNameResolver::shortClass($current->class->toString()) !== 'Route') {
            return;
        }
        if (!$current->name instanceof Node\Identifier) {
            return;
        }

        $middlewares = $stack['middleware'];
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

        $prefix = $stack['prefix'];
        if (isset($chain['prefix'])) {
            $prefix = $this->joinPrefix($prefix, $this->prefixString($chain['prefix'], $file, $node->getStartLine()));
        }

        $controller = $stack['controller'];
        if ($terminal === 'controller') {
            $ctrlArg = $current->args[0] ?? null;
            if ($ctrlArg instanceof Node\Arg) {
                $controller = PhpNameResolver::classItemName($ctrlArg->value, $uses, $namespace) ?? $controller;
            }
        }
        if (isset($chain['controller'])) {
            $controller = $this->chainController($chain, $uses, $namespace) ?? $controller;
        }

        if (isset($chain['group'])) {
            $this->processGroupArgs(
                $chain['group']->args,
                ['middleware' => $middlewares, 'prefix' => $prefix, 'controller' => $controller],
                $file,
                $uses,
                $namespace,
                $node->getStartLine()
            );

            return;
        }

        if ($terminal === 'group') {
            $this->processGroupArgs(
                $current->args,
                ['middleware' => $middlewares, 'prefix' => $prefix, 'controller' => $controller],
                $file,
                $uses,
                $namespace,
                $node->getStartLine()
            );

            return;
        }

        $this->recordRouteCall($node, $current, $chain, $terminal, $middlewares, $prefix, $controller, $file, $uses, $namespace);
    }

    /**
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     * @param array{middleware: list<string>, prefix: string, controller: string|null} $stack
     * @param array<string, string> $uses
     */
    private function processGroupArgs(
        array $args,
        array $stack,
        string $file,
        array $uses,
        ?string $namespace,
        int $line
    ): void {
        $extended = $stack;
        $first = $args[0] ?? null;
        $second = $args[1] ?? null;
        if ($first instanceof Node\Arg && $first->value instanceof Node\Expr\Array_) {
            $extended['middleware'] = array_merge($extended['middleware'], $this->groupArrayMiddleware($first->value));
            $extended['prefix'] = $this->joinPrefix($extended['prefix'], $this->groupArrayPrefix($first->value, $file, $line));
            $groupController = $this->groupArrayController($first->value, $uses, $namespace);
            if ($groupController !== null) {
                $extended['controller'] = $groupController;
            }
        }
        $closure = $second instanceof Node\Arg ? $second->value : ($first instanceof Node\Arg ? $first->value : null);
        if ($closure instanceof Node\Expr\Closure) {
            $this->walkStmts($closure->stmts, $extended, $file, $uses, $namespace);
        }
    }

    /**
     * @param array<string, Node\Expr\MethodCall> $chain
     * @param list<string> $middlewares
     * @param array<string, string> $uses
     */
    private function recordRouteCall(
        Node\Expr $node,
        Node\Expr\StaticCall $current,
        array $chain,
        string $terminal,
        array $middlewares,
        string $prefix,
        ?string $controller,
        string $file,
        array $uses,
        ?string $namespace
    ): void {
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
            $before = count($this->routes);
            $this->lastUnresolvedReason = null;
            $this->recordResource($verbNode, $chain, $middlewares, $prefix, $verb === 'apiresource', $controller, $file, $uses, $namespace);
            $this->account($before, 'resource-controller');

            return;
        }

        if ($verb === 'match') {
            $methods = $this->matchMethods($verbNode);
            if ($methods === []) {
                $this->account(count($this->routes), 'unsupported-expression');

                return;
            }
            $uriArg = $verbNode->args[1] ?? null;
            $actionArg = $verbNode->args[2] ?? null;
            $line = $verbNode->getStartLine();
        } else {
            if (!$verbNode instanceof Node\Expr\MethodCall && !$verbNode instanceof Node\Expr\StaticCall) {
                return;
            }
            // Route::any() answers every verb — expand so consumers can
            // match concrete methods without special-casing 'any'.
            $methods = $verb === 'any' ? self::ALL_VERBS : [$verb];
            $uriArg = $verbNode->args[0] ?? null;
            $actionArg = $verbNode->args[1] ?? null;
            $line = $verbNode->getStartLine();
        }

        if (!$actionArg instanceof Node\Arg) {
            return;
        }
        $before = count($this->routes);
        $this->lastUnresolvedReason = null;
        $uri = $uriArg instanceof Node\Arg ? $this->resolveUri($uriArg->value, $prefix, $file, $line) : null;
        $targets = $this->actionTargets($actionArg->value, $controller, $uses, $namespace, $file, $line);
        foreach ($targets as [$targetClass, $targetMethod]) {
            $this->routes[] = new RouteNode(
                $methods,
                $uri,
                $targetClass,
                $targetMethod,
                array_values(array_unique($middlewares)),
                $file,
                $line
            );
        }
        $this->account($before, $this->actionReason($actionArg->value));
    }

    /**
     * Coverage accounting for one route declaration: emitted nodes
     * count as resolved (full when URI and action are both known),
     * zero-node declarations count as unknown with a reason.
     */
    private function account(int $before, string $fallbackReason): void
    {
        ++$this->declarations;
        $emitted = array_slice($this->routes, $before);
        if ($emitted === []) {
            ++$this->unknownNodes;
            $reason = $this->lastUnresolvedReason ?? $fallbackReason;
            $this->unknownReasons[$reason] = ($this->unknownReasons[$reason] ?? 0) + 1;

            return;
        }
        $this->resolvedNodes += count($emitted);
        foreach ($emitted as $node) {
            if ($node->uri !== null && $node->controller !== null && $node->action !== null) {
                ++$this->fullNodes;
            }
        }
        $this->lastUnresolvedReason = null;
    }

    private function actionReason(Node\Expr $expr): string
    {
        if ($expr instanceof Node\Expr\Variable) {
            return 'dynamic-variable';
        }
        if ($expr instanceof Node\Expr\FuncCall) {
            return 'function-call';
        }
        if ($expr instanceof Node\Expr\Closure) {
            return 'closure-action';
        }

        return 'unsupported-expression';
    }

    /**
     * @return list<string> lowercase verbs, empty when unresolvable
     */
    private function matchMethods(Node\Expr\MethodCall|Node\Expr\StaticCall $node): array
    {
        $arg = $node->args[0] ?? null;
        if (!$arg instanceof Node\Arg) {
            return [];
        }
        if ($arg->value instanceof Node\Scalar\String_) {
            $verb = strtolower($arg->value->value);

            return in_array($verb, self::ALL_VERBS, true) ? [$verb] : [];
        }
        if ($arg->value instanceof Node\Expr\Array_) {
            $out = [];
            foreach ($arg->value->items as $item) {
                if (
                    $item instanceof Node\Expr\ArrayItem
                    && $item->value instanceof Node\Scalar\String_
                    && in_array(strtolower($item->value->value), self::ALL_VERBS, true)
                ) {
                    $out[] = strtolower($item->value->value);
                }
            }

            return array_values(array_unique($out));
        }

        return [];
    }

    /**
     * @param array<string, Node\Expr\MethodCall> $chain
     * @param list<string> $middlewares
     * @param array<string, string> $uses
     */
    private function recordResource(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        array $chain,
        array $middlewares,
        string $prefix,
        bool $api,
        ?string $controller,
        string $file,
        array $uses,
        ?string $namespace
    ): void {
        $nameArg = $call->args[0] ?? null;
        $controllerArg = $call->args[1] ?? null;
        if (
            !$nameArg instanceof Node\Arg
            || !$nameArg->value instanceof Node\Scalar\String_
            || !$controllerArg instanceof Node\Arg
        ) {
            $this->lastUnresolvedReason = 'dynamic-expression';

            return;
        }
        $resolved = $controller;
        if ($controllerArg->value instanceof Node\Expr\ClassConstFetch && $controllerArg->value->class instanceof Node\Name) {
            $resolved = PhpNameResolver::resolveName($controllerArg->value->class->toString(), $uses, $namespace);
        } elseif ($controllerArg->value instanceof Node\Scalar\String_ && str_contains($controllerArg->value->value, '@')) {
            $resolved = $controller;
        } elseif (
            !$controllerArg->value instanceof Node\Expr\ClassConstFetch
            && !$controllerArg->value instanceof Node\Scalar\String_
        ) {
            // Variable / dynamic controller (e.g. BREAD `$breadController`
            // varying per loop iteration): resolve only when proven.
            $constant = $this->resolveConstant(
                $controllerArg->value,
                $file,
                $controllerArg->getStartLine()
            );
            if ($constant !== null && $constant->value !== '') {
                $resolved = PhpNameResolver::resolveName($constant->value, $uses, $namespace);
            }
        }
        if ($resolved === null) {
            $this->lastUnresolvedReason = $this->actionReason($controllerArg->value);

            return;
        }

        $only = null;
        $except = [];
        // only()/except() come either as a third options array
        // (['only' => [...]]) or as chained ->only([...]) calls whose
        // argument is a bare list of names.
        $optionsArg = $call->args[2] ?? null;
        if ($optionsArg instanceof Node\Arg && $optionsArg->value instanceof Node\Expr\Array_) {
            foreach ($optionsArg->value->items as $item) {
                if (
                    !$item instanceof Node\Expr\ArrayItem
                    || !$item->key instanceof Node\Scalar\String_
                    || !$item->value instanceof Node\Expr\Array_
                ) {
                    continue;
                }
                $names = $this->nameList($item->value);
                if ($item->key->value === 'only') {
                    $only = $names;
                } elseif ($item->key->value === 'except') {
                    $except = $names;
                }
            }
        }
        foreach (['only', 'except'] as $filter) {
            if (!isset($chain[$filter])) {
                continue;
            }
            $filterArg = $chain[$filter]->args[0] ?? null;
            if (!$filterArg instanceof Node\Arg || !$filterArg->value instanceof Node\Expr\Array_) {
                continue;
            }
            $names = $this->nameList($filterArg->value);
            if ($filter === 'only') {
                $only = $names;
            } else {
                $except = $names;
            }
        }

        $methods = $api ? self::API_RESOURCE_METHODS : array_keys(self::RESOURCE_METHODS);
        foreach ($methods as $method) {
            $lower = strtolower($method);
            if ($only !== null && !in_array($lower, $only, true)) {
                continue;
            }
            if (in_array($lower, $except, true)) {
                continue;
            }
            [$verb, $suffix] = self::RESOURCE_METHODS[$method];
            $verbs = [$verb];
            // PUT/PATCH share the update route.
            if ($lower === 'update') {
                $verbs = ['put', 'patch'];
            }
            $this->routes[] = new RouteNode(
                $verbs,
                $this->joinPrefix($prefix, $nameArg->value->value . $suffix),
                $resolved,
                $method,
                array_values(array_unique($middlewares)),
                $file,
                $call->getStartLine()
            );
        }
    }

    /**
     * Lowercased string items of an array expression. Non-literal items
     * are dropped, never guessed.
     *
     * @return list<string>
     */
    private function nameList(Node\Expr\Array_ $array): array
    {
        $names = [];
        foreach ($array->items as $sub) {
            if ($sub instanceof Node\Expr\ArrayItem && $sub->value instanceof Node\Scalar\String_) {
                $names[] = strtolower($sub->value->value);
            }
        }

        return $names;
    }

    /**
     * Resolve [class, action] targets. Unknown actions resolve to null —
     * never guessed.
     *
     * @param array<string, string> $uses
     * @return list<array{string|null, string|null}>
     */
    private function actionTargets(
        ?Node\Expr $expr,
        ?string $controller,
        array $uses,
        ?string $namespace,
        string $file,
        int $line
    ): array {
        if ($expr === null) {
            return [];
        }
        if ($expr instanceof Node\Scalar\String_) {
            if (str_contains($expr->value, '@')) {
                [$class, $method] = explode('@', $expr->value, 2);
                if ($class === '' || $method === '') {
                    return [];
                }

                return [[PhpNameResolver::resolveName($class, $uses, $namespace), $method]];
            }
            if ($controller !== null && $expr->value !== '') {
                return [[$controller, $expr->value]];
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
                if (!$methodItem->value instanceof Node\Scalar\String_) {
                    return [];
                }
                $class = PhpNameResolver::classItemName($classItem->value, $uses, $namespace);
                if ($class === null) {
                    return [];
                }

                return [[$class, $methodItem->value->value]];
            }

            foreach ($expr->items as $item) {
                if (
                    $item instanceof Node\Expr\ArrayItem
                    && $item->key instanceof Node\Scalar\String_
                    && $item->key->value === 'uses'
                ) {
                    return $this->actionTargets($item->value, $controller, $uses, $namespace, $file, $line);
                }
            }

            return [];
        }

        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            return [[PhpNameResolver::resolveName($expr->class->toString(), $uses, $namespace), '__invoke']];
        }

        if ($expr instanceof Node\Expr\Closure) {
            return [[null, null]];
        }

        // Proven-constant fallback for variables, concatenations and
        // other scalar shapes (`$namespacePrefix . 'X@login'`): resolve
        // exactly like a literal, otherwise stay unknown.
        $constant = $this->resolveConstant($expr, $file, $line);
        if ($constant === null || $constant->value === '') {
            return [];
        }

        return $this->actionTargets(new Node\Scalar\String_($constant->value), $controller, $uses, $namespace, $file, $line);
    }

    /**
     * Resolve a URI expression against the accumulated prefix. Plain
     * strings resolve directly; proven-constant expressions (variables,
     * concatenations) resolve via the constant resolver; anything
     * dynamic resolves to null (unknown, never guessed).
     */
    private function resolveUri(Node\Expr $expr, string $prefix, string $file, int $line): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $this->joinPrefix($prefix, $expr->value);
        }
        $constant = $this->resolveConstant($expr, $file, $line);
        if ($constant === null) {
            return null;
        }

        return $this->joinPrefix($prefix, $constant->value);
    }

    private function joinPrefix(string $prefix, ?string $uri): ?string
    {
        if ($uri === null) {
            return null;
        }
        $combined = rtrim($prefix, '/') . '/' . ltrim($uri, '/');
        if ($combined === '/') {
            return '/';
        }

        return '/' . ltrim($combined, '/');
    }

    /**
     * @param array{middleware: list<string>, prefix: string, controller: string|null} $stack
     * @param array<string, string> $uses
     */
    private function collectRequiredRouteFile(
        Node\Expr\Include_ $include,
        array $stack,
        string $file,
        array $uses,
        ?string $namespace
    ): void {
        $path = $this->includePath($include, dirname($file), $file);
        if ($path === null || isset($this->visited[$path])) {
            return;
        }
        $this->visited[$path] = true;
        $nodes = $this->nodesOf($path);
        if ($nodes === null) {
            return;
        }
        $innerNodes = PhpNameResolver::nodeList($nodes);
        $this->walkStmts($innerNodes, $stack, $path, PhpNameResolver::useMap($innerNodes, $this->finder), PhpNameResolver::namespaceOf($innerNodes, $this->finder));
    }

    /**
     * @param list<Node> $ast
     * @return list<string> realpaths of required files
     */
    private function collectRequiredFiles(array $ast, string $dir, string $file): array
    {
        $out = [];
        $includes = $this->finder()->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\Include_;
        });
        foreach ($includes as $include) {
            if (!$include instanceof Node\Expr\Include_) {
                continue;
            }
            $path = $this->includePath($include, $dir, $file);
            if ($path !== null) {
                $out[] = $path;
            }
        }

        return $out;
    }

    private function includePath(Node\Expr\Include_ $include, string $dir, string $file): ?string
    {
        $target = $this->includeTarget($include, $file);
        if ($target === null) {
            return null;
        }
        // Proven-constant targets may already be absolute (__DIR__-based).
        if (PhpNameResolver::isAbsolutePath($target) && is_file($target)) {
            $real = realpath($target);

            return $real === false ? null : $real;
        }
        $candidate = $dir . DIRECTORY_SEPARATOR . $target;
        if (is_file($candidate)) {
            $real = realpath($candidate);

            return $real === false ? null : $real;
        }
        $relative = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $target), DIRECTORY_SEPARATOR);
        $probe = $dir;
        for ($depth = 0; $depth < 8; ++$depth) {
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

    private function includeTarget(Node\Expr\Include_ $include, string $file): ?string
    {
        if ($include->expr instanceof Node\Scalar\String_) {
            return $include->expr->value === '' ? null : $include->expr->value;
        }

        // require __DIR__ . '/admin.php', base_path('...') and
        // proven-constant variables — all through one resolver.
        $constant = $this->resolveConstant($include->expr, $file, $include->getStartLine());
        if ($constant === null || $constant->value === '') {
            $this->lastUnresolvedReason = 'unresolved-include';

            return null;
        }

        return $constant->value;
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

    private function groupArrayPrefix(Node\Expr\Array_ $config, string $file, int $line): string
    {
        foreach ($config->items as $item) {
            if (
                $item instanceof Node\Expr\ArrayItem
                && $item->key instanceof Node\Scalar\String_
                && $item->key->value === 'prefix'
            ) {
                if ($item->value instanceof Node\Scalar\String_) {
                    return $item->value->value;
                }
                $constant = $this->resolveConstant($item->value, $file, $line);
                if ($constant !== null) {
                    return $constant->value;
                }
            }
        }

        return '';
    }

    /**
     * Prefix from a `->prefix('admin')` chain link. Proven-constant
     * expressions resolve; anything else yields '' (unknown segments
     * are dropped, never guessed).
     */
    private function prefixString(Node\Expr\MethodCall $link, string $file, int $line): string
    {
        $arg = $link->args[0] ?? null;
        if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
            return $arg->value->value;
        }
        if ($arg instanceof Node\Arg) {
            $constant = $this->resolveConstant($arg->value, $file, $line);
            if ($constant !== null) {
                return $constant->value;
            }
        }

        return '';
    }

    /**
     * @param array<string, string> $uses
     */
    private function groupArrayController(Node\Expr\Array_ $config, array $uses, ?string $namespace): ?string
    {
        foreach ($config->items as $item) {
            if (
                !$item instanceof Node\Expr\ArrayItem
                || !$item->key instanceof Node\Scalar\String_
                || $item->key->value !== 'controller'
            ) {
                continue;
            }
            if ($item->value instanceof Node\Expr\ClassConstFetch && $item->value->class instanceof Node\Name) {
                return PhpNameResolver::resolveName($item->value->class->toString(), $uses, $namespace);
            }
            if ($item->value instanceof Node\Scalar\String_ && $item->value->value !== '') {
                return PhpNameResolver::resolveName($item->value->value, $uses, $namespace);
            }
        }

        return null;
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

        return PhpNameResolver::classItemName($arg->value, $uses, $namespace);
    }

    private function isRouteGroupCall(Node $node): bool
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
            && PhpNameResolver::shortClass($current->class->toString()) === 'Route';
    }

    /**
     * @return list<Node\Expr\MethodCall|Node\Expr\StaticCall>
     */
    private function callsInArgs(Node $node): array
    {
        if (!$node instanceof Node\Expr\MethodCall && !$node instanceof Node\Expr\StaticCall) {
            return [];
        }
        $out = [];
        foreach ($node->args as $arg) {
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            $found = $this->finder->find($arg->value, static function (Node $inner): bool {
                return $inner instanceof Node\Expr\MethodCall || $inner instanceof Node\Expr\StaticCall;
            });
            foreach ($found as $inner) {
                if ($inner instanceof Node\Expr\MethodCall || $inner instanceof Node\Expr\StaticCall) {
                    $out[] = $inner;
                }
            }
        }

        return $out;
    }
}
