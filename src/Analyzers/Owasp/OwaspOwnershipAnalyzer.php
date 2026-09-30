<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Analysis\ScopeIds;
use Rampart\QualityChecker\Analysis\StructuralFactIndex;
use Rampart\QualityChecker\Semantic\LaravelSemanticIndex;
use Rampart\QualityChecker\Semantic\MiddlewareRegistry;
use Rampart\QualityChecker\Semantic\MiddlewareTaxonomy;
use Rampart\QualityChecker\Semantic\OwnershipDecision;
use Rampart\QualityChecker\Semantic\OwnershipShadow;
use Rampart\QualityChecker\Semantic\RouteNode;

/**
 * A01 object-level authorization (IDOR) — v0.6.1 SHADOW mode.
 *
 * Records one OwnershipDecision per controller action performing a
 * sensitive write (update/delete/destroy/restore/forceDelete) on a
 * request-identified resource. Emits ZERO Issue objects; the sidecar
 * report comes from OwnershipShadow.
 *
 * Evidenceichael (bounded, structural — no guessing):
 * - relationship-scoped query ($user->links()->...->delete(),
 *   Model::where(user_id, authId)->...),
 * - where(owner_column, currentUser),
 * - explicit owner comparison + deny in-method or in route
 *   middleware ($user->id != $link->user_id → abort/403),
 * - Policy/Gate ($this->authorize(), Gate::*, can: middleware).
 * Auth alone is never ownership. Service returns, tenant/team
 * multi-hop, polymorphic ownership and custom middleware stay
 * UNKNOWN/REVIEW.
 *
 * Reuses the canonical AST, StructuralFactIndex and ScopeIds — no new
 * full-tree traversals (per-method subtree scans only).
 */
final class OwaspOwnershipAnalyzer extends AbstractAnalyzer
{
    /** @var list<string> sensitive write operations (lowercased) */
    private const SENSITIVE_OPS = ['delete', 'update', 'destroy', 'restore', 'forcedelete'];

    /** @var list<string> owner columns recognized in where() */
    private const OWNER_COLUMNS = ['user_id', 'owner_id', 'created_by'];

    /** @var list<string> methods that never open an owned relation */
    private const NON_RELATION_METHODS = ['can', 'cannot', 'authorize', 'allows', 'denies', 'check'];

    private ?StructuralFactIndex $facts = null;

    private function facts(): StructuralFactIndex
    {
        if ($this->facts === null) {
            $this->facts = new StructuralFactIndex();
            $this->facts->setScanContext($this->sharedScanContext());
        }

        return $this->facts;
    }

    public function analyze(array $files): array
    {
        $scan = $this->sharedScanContext();
        $index = (new LaravelSemanticIndex($scan))->build($files);
        $registry = new MiddlewareRegistry();
        $registry->setScanContext($scan);
        $registry->build($files);

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $this->analyzeFile($file, $index, $registry);
        }

        return [];
    }

    public function supports(string $path): bool
    {
        if (strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) !== 'php') {
            return false;
        }
        $normalized = strtolower(str_replace('\\', '/', $path));

        return !str_contains($normalized, '/tests/')
            && !str_contains($normalized, '/vendor/')
            && !str_contains($normalized, '/database/seeders/')
            && !str_contains($normalized, '/database/factories/')
            && !str_contains($normalized, '/database/migrations/');
    }

    private function analyzeFile(
        string $file,
        LaravelSemanticIndex $index,
        MiddlewareRegistry $registry
    ): void {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return;
        }
        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }
        $namespace = $this->namespaceOf($nodes);
        foreach ($this->finder()->findInstanceOf($nodes, Node\Stmt\Class_::class) as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            $controller = $class->name instanceof Node\Identifier
                ? ($namespace !== null ? $namespace . '\\' . $class->name->toString() : $class->name->toString())
                : '';
            foreach ($class->stmts as $stmt) {
                if (!$stmt instanceof Node\Stmt\ClassMethod || !$stmt->isPublic() || $stmt->isMagic()) {
                    continue;
                }
                $this->analyzeAction($file, $controller, $stmt, $index, $registry);
            }
        }
    }

    private function isControllerClass(Node\Stmt\Class_ $class): bool
    {
        if ($class->name === null || $class->name->toString() === '' || $class->isAbstract()) {
            return false;
        }

        return str_ends_with($class->name->toString(), 'Controller');
    }

    /**
     * One shadow decision per action (worst sink wins).
     */
    private function analyzeAction(
        string $file,
        string $controller,
        Node\Stmt\ClassMethod $method,
        LaravelSemanticIndex $index,
        MiddlewareRegistry $registry
    ): void {
        $methodName = $method->name->toString();
        $sinks = [];
        foreach ($this->facts()->callsAny($file) as $call) {
            if (!$this->isWithinMethod($call, $method)) {
                continue;
            }
            $name = $this->callName($call);
            if ($name === null || !in_array(strtolower($name), self::SENSITIVE_OPS, true)) {
                continue;
            }
            if (!$call instanceof Node\Expr\MethodCall && !$call instanceof Node\Expr\StaticCall) {
                continue;
            }
            $sinks[] = $call;
        }
        if ($sinks === []) {
            return;
        }

        $routes = $index->routesForAction($controller, $methodName);
        $middleware = $this->routeMiddleware($routes);
        $requestVars = $this->requestDerivedVars($file, $method);
        $principal = $this->findPrincipal($method, $middleware);

        $worst = null;
        foreach ($sinks as $sink) {
            $candidate = $this->evaluateSink($file, $controller, $methodName, $method, $sink, $routes, $middleware, $requestVars, $principal, $registry);
            if ($candidate === null) {
                continue;
            }
            if ($worst === null || $this->worseThan($candidate->status, $worst->status)) {
                $worst = $candidate;
            }
        }
        if ($worst !== null) {
            OwnershipShadow::record($worst);
        }
    }

    private function worseThan(string $a, string $b): bool
    {
        $rank = [
            OwnershipDecision::PROTECTED => 0,
            OwnershipDecision::UNKNOWN => 1,
            OwnershipDecision::REVIEW => 2,
            OwnershipDecision::EXPOSED => 3,
        ];

        return ($rank[$a] ?? 1) > ($rank[$b] ?? 1);
    }

    /**
     * @param list<RouteNode> $routes
     * @param list<string> $middleware
     * @param array<string, array{kind: string, detail: string, line: int|null}> $requestVars
     * @param array{kind: string, detail: string}|null $principal
     */
    private function evaluateSink(
        string $file,
        string $controller,
        string $methodName,
        Node\Stmt\ClassMethod $method,
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        array $routes,
        array $middleware,
        array $requestVars,
        ?array $principal,
        MiddlewareRegistry $registry
    ): ?OwnershipDecision {
        $opName = $this->callName($sink) ?? 'unknown()';
        $sinkLine = $sink->getStartLine();

        // Identifier: request-controlled id reaching the lookup/operation.
        $identifier = $this->findIdentifier($sink, $method, $requestVars);
        // Lookup: model-ish root of the receiver chain (best effort).
        $lookup = $this->classifyLookup($sink, $method);
        if ($identifier === null && $lookup === null) {
            // No request signal and no model signal — not IDOR-relevant.
            return null;
        }

        $trace = [];
        if ($identifier !== null) {
            $trace[] = ['kind' => 'identifier', 'detail' => $identifier['detail'], 'line' => $identifier['line']];
        }
        if ($lookup !== null) {
            $trace[] = ['kind' => 'lookup', 'detail' => $lookup['detail'], 'line' => $lookup['line']];
        }
        $trace[] = ['kind' => 'operation', 'detail' => $opName, 'line' => $sinkLine];

        $ownershipEvidence = $this->ownershipEvidence($file, $method, $sink, $requestVars, $principal, $middleware, $registry);
        $authorizationEvidence = $this->authorizationEvidence($method, $sink, $middleware);

        $authenticated = $principal !== null || $this->hasAuthMiddleware($middleware);
        $gated = $this->hasGateMiddleware($middleware);
        if ($ownershipEvidence !== [] || $authorizationEvidence !== []) {
            $status = OwnershipDecision::PROTECTED;
            $confidence = 'high';
            $reason = $this->firstMechanism($ownershipEvidence, $authorizationEvidence);
        } elseif ($routes === []) {
            $status = OwnershipDecision::UNKNOWN;
            $confidence = 'high';
            $reason = $this->reviewReason($controller, $middleware, $method, $sink, $identifier, $lookup, $principal);
        } elseif ($authenticated || $gated) {
            // Authenticated (or custom-gated, unproven in v0.6.1) but
            // ownership unproven — deleteLink lives here.
            $status = OwnershipDecision::REVIEW;
            $confidence = 'medium';
            $reason = $this->reviewReason($controller, $middleware, $method, $sink, $identifier, $lookup, $principal);
        } elseif ($this->hasNoAuth($middleware)) {
            $status = OwnershipDecision::EXPOSED;
            $confidence = 'high';
            $reason = 'NO_AUTH';
        } else {
            $status = OwnershipDecision::UNKNOWN;
            $confidence = 'medium';
            $reason = $this->reviewReason($controller, $middleware, $method, $sink, $identifier, $lookup, $principal);
        }

        $routeRef = null;
        if ($routes !== []) {
            $first = $routes[0];
            $routeRef = [
                'methods' => $first->methods ?? [],
                'uri' => $first->uri ?? null,
                'file' => $first->file ?? $file,
                'line' => $first->line ?? null,
            ];
        }

        return new OwnershipDecision(
            $status,
            $controller,
            $methodName,
            $file,
            $sinkLine,
            $routeRef,
            $middleware,
            $identifier,
            $lookup,
            ['kind' => 'sensitive-write', 'detail' => $opName],
            $principal,
            $ownershipEvidence,
            $authorizationEvidence,
            $confidence,
            $trace,
            $reason,
        );
    }

    /**
     * @param list<array{mechanism: string, detail: string, confidence: string}> $ownership
     * @param list<array{mechanism: string, detail: string, confidence: string}> $authorization
     */
    private function firstMechanism(array $ownership, array $authorization): string
    {
        if (isset($ownership[0]['mechanism'])) {
            return $ownership[0]['mechanism'];
        }
        if (isset($authorization[0]['mechanism'])) {
            return 'auth:' . $authorization[0]['mechanism'];
        }

        return 'PROTECTED';
    }

    /**
     * Calibration bucket (v0.6.1b): why is this REVIEW/UNKNOWN — the
     * single most actionable label, highest priority first. Labeling
     * only; never changes the verdict.
     *
     * @param list<string> $middleware
     * @param array{kind: string, detail: string, line: int|null}|null $identifier
     * @param array{kind: string, detail: string, line: int|null}|null $lookup
     * @param array{kind: string, detail: string}|null $principal
     */
    private function reviewReason(
        string $controller,
        array $middleware,
        Node\Stmt\ClassMethod $method,
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        ?array $identifier,
        ?array $lookup,
        ?array $principal
    ): string {
        if ($this->hasLateAuthorization($method, $sink->getStartLine())) {
            return 'AUTHORIZATION_AFTER_SINK';
        }
        $short = strtolower((string) substr($controller, (int) strrpos($controller, '\\') + 1));
        if (str_starts_with($short, 'admin')) {
            return 'ADMIN_CONTEXT';
        }
        foreach ($middleware as $item) {
            if (str_contains(strtolower($item), 'admin')) {
                return 'ADMIN_CONTEXT';
            }
        }
        if ($this->hasGateMiddleware($middleware)) {
            return 'CUSTOM_MIDDLEWARE';
        }
        if ($identifier === null || $lookup === null || $lookup['kind'] === 'dynamic') {
            return 'UNRESOLVED_RESOURCE';
        }
        if ($principal === null) {
            return 'UNRESOLVED_PRINCIPAL';
        }

        return 'AUTH_ONLY';
    }

    /**
     * An authorize/Gate/can call positioned at or after the sink —
     * explains REVIEWs where authorization exists but proves nothing.
     */
    private function hasLateAuthorization(Node\Stmt\ClassMethod $method, int $sinkLine): bool
    {
        $found = $this->finder()->find($method->stmts ?? [], static function (Node $node): bool {
            if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                $class = strtolower(ltrim($node->class->toString(), '\\'));
                if (($class === 'gate' || str_ends_with($class, '\\gate')) && $node->name instanceof Node\Identifier) {
                    return in_array(strtolower($node->name->toString()), ['allows', 'authorize', 'check', 'any', 'denies'], true);
                }

                return false;
            }
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array(strtolower($node->name->toString()), ['authorize', 'authorizeresource', 'can', 'cannot'], true);
            }

            return false;
        });
        foreach ($found as $node) {
            if ($node->getStartLine() >= $sinkLine) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<RouteNode> $routes
     * @return list<string> union of route middleware stacks
     */
    private function routeMiddleware(array $routes): array
    {
        $out = [];
        foreach ($routes as $route) {
            foreach ($route->middleware ?? [] as $middleware) {
                $out[$middleware] = true;
            }
        }

        return array_keys($out);
    }

    /**
     * @param list<string> $middleware
     */
    private function hasAuthMiddleware(array $middleware): bool
    {
        foreach ($middleware as $item) {
            if (MiddlewareTaxonomy::classify($item, []) === MiddlewareTaxonomy::AUTHENTICATION) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $middleware
     */
    private function hasGateMiddleware(array $middleware): bool
    {
        foreach ($middleware as $item) {
            if (MiddlewareTaxonomy::classify($item, []) === MiddlewareTaxonomy::GATE) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $middleware
     */
    private function hasNoAuth(array $middleware): bool
    {
        foreach ($middleware as $item) {
            $kind = MiddlewareTaxonomy::classify($item, []);
            if ($kind === MiddlewareTaxonomy::AUTHENTICATION || $kind === MiddlewareTaxonomy::AUTHORIZATION) {
                return false;
            }
        }

        return true;
    }

    private function isWithinMethod(Node $node, Node\Stmt\ClassMethod $method): bool
    {
        return ScopeIds::isWithin($node, $method);
    }

    private function callName(Node\Expr $call): ?string
    {
        if (
            ($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\StaticCall)
            && $call->name instanceof Node\Identifier
        ) {
            return $call->name->toString();
        }
        if ($call instanceof Node\Expr\FuncCall && $call->name instanceof Node\Name) {
            return $call->name->toString();
        }

        return null;
    }

    /**
     * Variables derived from the request in this method: direct
     * `$v = $request->...` assigns (straight-line, above use) plus
     * method parameters (route inputs, incl. Model-typed implicit
     * bindings — the id is still route-controlled).
     *
     * @return array<string, array{kind: string, detail: string, line: int|null}>
     */
    private function requestDerivedVars(string $file, Node\Stmt\ClassMethod $method): array
    {
        $out = [];
        foreach ($method->params as $param) {
            if ($param instanceof Node\Param && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                // The $request object itself is the input source, not a
                // derived identifier — structural checks handle it.
                if (strtolower($param->var->name) === 'request') {
                    continue;
                }
                $type = $param->type instanceof Node\Name ? $param->type->toString() : ($param->type instanceof Node\Identifier ? $param->type->toString() : null);
                $out[$param->var->name] = [
                    'kind' => $type !== null && !$this->isBuiltinType($type) ? 'model-binding' : 'route-param',
                    'detail' => '$' . $param->var->name . ($type !== null ? " ({$type})" : ''),
                    'line' => $param->getStartLine(),
                ];
            }
        }
        foreach ($this->facts()->assignsAndIfs($file) as $node) {
            if (!$node instanceof Node\Expr\Assign) {
                continue;
            }
            if (!ScopeIds::isWithin($node, $method)) {
                continue;
            }
            if (!$node->var instanceof Node\Expr\Variable || !is_string($node->var->name)) {
                continue;
            }
            if ($this->isRequestExpr($node->expr, array_keys($out))) {
                $out[$node->var->name] = [
                    'kind' => 'request-var',
                    'detail' => '$' . $node->var->name . ' = request input',
                    'line' => $node->getStartLine(),
                ];
            }
        }

        return $out;
    }

    private function isBuiltinType(string $type): bool
    {
        return in_array(strtolower(ltrim($type, '\\')), ['int', 'string', 'bool', 'float', 'array', 'callable', 'iterable', 'object', 'mixed', 'void', 'null'], true);
    }

    /**
     * Structural request-input check (no traversal): $request->*,
     * $request->input/get/query/route(...), request() helper, or a
     * variable already known request-derived.
     *
     * @param list<string> $knownVars
     */
    private function isRequestExpr(Node\Expr $expr, array $knownVars): bool
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, ['request', ...$knownVars], true);
        }
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return strtolower($expr->name->toString()) === 'request';
        }
        if ($expr instanceof Node\Expr\PropertyFetch) {
            // $request->id / $request->up (route + query inputs).
            return $expr->var instanceof Node\Expr\Variable
                && is_string($expr->var->name)
                && in_array($expr->var->name, ['request', ...$knownVars], true);
        }
        if ($expr instanceof Node\Expr\MethodCall) {
            return $expr->var instanceof Node\Expr\Variable
                && is_string($expr->var->name)
                && in_array($expr->var->name, ['request', ...$knownVars], true);
        }

        return false;
    }

    /**
     * Authenticated principal in this method, if any. Presence only —
     * never ownership evidence by itself.
     *
     * @param list<string> $middleware
     * @return array{kind: string, detail: string}|null
     */
    private function findPrincipal(Node\Stmt\ClassMethod $method, array $middleware): ?array
    {
        if ($this->hasAuthMiddleware($middleware)) {
            return ['kind' => 'auth-middleware', 'detail' => 'authenticated route'];
        }
        $found = $this->finder()->find($method->stmts ?? [], static function (Node $node): bool {
            if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                $class = strtolower(ltrim($node->class->toString(), '\\'));
                if (($class === 'auth' || str_ends_with($class, '\\auth')) && $node->name instanceof Node\Identifier) {
                    return in_array(strtolower($node->name->toString()), ['user', 'id', 'check'], true);
                }
            }
            if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                return strtolower($node->name->toString()) === 'auth';
            }

            return $node instanceof Node\Expr\MethodCall
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === 'request'
                && $node->name instanceof Node\Identifier
                && strtolower($node->name->toString()) === 'user';
        });
        if ($found === []) {
            return null;
        }

        return ['kind' => 'in-method', 'detail' => 'Auth::user()/auth()/$request->user()'];
    }

    /**
     * Request-controlled identifier reaching the sink: a request-derived
     * variable/method-param used in the receiver chain or arguments, or
     * a direct $request expression in them.
     *
     * @param array<string, array{kind: string, detail: string, line: int|null}> $requestVars
     * @return array{kind: string, detail: string, line: int|null}|null
     */
    private function findIdentifier(
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        Node\Stmt\ClassMethod $method,
        array $requestVars
    ): ?array {
        $chain = [$sink, ...$this->receiverChain($sink)];
        foreach ($chain as $node) {
            foreach ($this->finder()->find($node, static fn (Node $n): bool => $n instanceof Node\Expr\Variable) as $var) {
                if (!$var instanceof Node\Expr\Variable || !is_string($var->name)) {
                    continue;
                }
                if (isset($requestVars[$var->name])) {
                    $info = $requestVars[$var->name];

                    return ['kind' => $info['kind'], 'detail' => $info['detail'], 'line' => $var->getStartLine()];
                }
            }
            foreach ($this->finder()->find($node, fn (Node $n): bool => $n instanceof Node\Expr && $this->isRequestExpr($n, [])) as $req) {
                if ($req instanceof Node\Expr\Variable && is_string($req->name) && $req->name === 'request') {
                    continue;
                }

                return ['kind' => 'request-expr', 'detail' => 'request input in sink chain', 'line' => $req->getStartLine()];
            }
        }

        // Two-step lookup: $group = Group::find($id); ... $group->delete().
        // Resolve the receiver variable's straight-line assignment above
        // the sink and inspect its RHS for request input.
        $root = $this->chainRoot($sink);
        if ($root instanceof Node\Expr\Variable && is_string($root->name) && !isset($requestVars[$root->name])) {
            foreach ($this->finder()->find($method->stmts ?? [], static fn (Node $n): bool => $n instanceof Node\Expr\Assign) as $assign) {
                if (!$assign instanceof Node\Expr\Assign) {
                    continue;
                }
                if (
                    !$assign->var instanceof Node\Expr\Variable
                    || $assign->var->name !== $root->name
                    || $assign->getStartLine() >= $sink->getStartLine()
                    || !ScopeIds::isWithin($assign, $method)
                ) {
                    continue;
                }
                foreach ($this->finder()->find($assign->expr, static fn (Node $n): bool => $n instanceof Node\Expr\Variable) as $var) {
                    if (!$var instanceof Node\Expr\Variable || !is_string($var->name)) {
                        continue;
                    }
                    // Bare $request is the source object, not an id.
                    if (strtolower($var->name) === 'request') {
                        continue;
                    }
                    if (isset($requestVars[$var->name])) {
                        $info = $requestVars[$var->name];

                        return ['kind' => $info['kind'], 'detail' => $info['detail'] . " via \${$root->name}", 'line' => $var->getStartLine()];
                    }
                }
                // Direct request expressions in the RHS ($request->id,
                // $request->input(), request()->...).
                foreach ($this->finder()->find($assign->expr, fn (Node $n): bool => $n instanceof Node\Expr && $this->isRequestExpr($n, array_keys($requestVars))) as $req) {
                    if ($req instanceof Node\Expr\Variable) {
                        continue;
                    }

                    return ['kind' => 'request-expr', 'detail' => "request input via \${$root->name}", 'line' => $req->getStartLine()];
                }
            }
        }

        return null;
    }

    /**
     * Receiver chain roots: unwrap ->var / ::class links to the root
     * expression (Model::where, $user->links, $link, ...).
     *
     * @return list<Node\Expr>
     */
    private function receiverChain(Node\Expr $call): array
    {
        $out = [];
        $current = $call;
        while (true) {
            if ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
                $current = $current->var;
            } elseif ($current instanceof Node\Expr\StaticCall) {
                break;
            } else {
                break;
            }
            if ($current instanceof Node\Expr) {
                $out[] = $current;
            } else {
                break;
            }
        }

        return $out;
    }

    /**
     * Best-effort lookup classification (structural, no guessing).
     *
     * @return array{kind: string, detail: string, line: int|null}|null
     */
    private function classifyLookup(
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        Node\Stmt\ClassMethod $method
    ): ?array {
        $chain = [$sink, ...$this->receiverChain($sink)];
        foreach ($chain as $node) {
            if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                $class = $node->class->toString();
                $name = $node->name instanceof Node\Identifier ? strtolower($node->name->toString()) : '';
                if (in_array($name, ['find', 'findorfail', 'where', 'query', 'destroy'], true)) {
                    return ['kind' => 'model-query', 'detail' => $class . '::' . $name . '()', 'line' => $node->getStartLine()];
                }
                // Service/facade lookup — ownership unprovable here.
                return ['kind' => 'dynamic', 'detail' => $class . ' (non-model lookup)', 'line' => $node->getStartLine()];
            }
            if ($node instanceof Node\Expr\MethodCall && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
                $var = $node->var->name;
                if (in_array($var, ['user', 'request'], true)) {
                    continue;
                }

                return ['kind' => 'variable-model', 'detail' => '$' . $var . '->...', 'line' => $node->getStartLine()];
            }
        }

        return null;
    }

    /**
     * @param list<Node> $nodes
     */
    private function namespaceOf(array $nodes): ?string
    {
        foreach ($this->finder()->find($nodes, static fn (Node $n): bool => $n instanceof Node\Stmt\Namespace_) as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }

    /**
     * In-method ownership evidence (bounded, structural). Custom route
     * middleware is deliberately NOT proven here — even an ownership-
     * shaped handle() (e.g. LinkId) stays a review trail in v0.6.1, so
     * the method body must prove ownership by itself.
     *
     * @param array<string, array{kind: string, detail: string, line: int|null}> $requestVars
     * @param array{kind: string, detail: string}|null $principal
     * @param list<string> $middleware
     * @return list<array{mechanism: string, detail: string, confidence: string}>
     */
    private function ownershipEvidence(
        string $file,
        Node\Stmt\ClassMethod $method,
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        array $requestVars,
        ?array $principal,
        array $middleware,
        MiddlewareRegistry $registry
    ): array {
        $evidence = [];
        $chain = [$sink, ...$this->receiverChain($sink)];

        // 1. Relationship-scoped receiver: $user->relation()->...->op,
        // Auth::user()->relation()->..., $request->user()->relation().
        foreach ($chain as $node) {
            $root = $this->chainRoot($node);
            if ($root !== null && $this->isPrincipalRoot($root) && $this->hasRelationHop($node, $root)) {
                $evidence[] = [
                    'mechanism' => 'relationship-scoped',
                    'detail' => 'receiver rooted at authenticated principal with relation hop',
                    'confidence' => 'high',
                ];
                break;
            }
        }

        // 2. where(owner_column, currentUser) in the sink chain or method.
        if ($this->hasOwnerWhere($chain, $method)) {
            $evidence[] = [
                'mechanism' => 'owner-where',
                'detail' => 'where(user_id|owner_id|created_by, current-user)',
                'confidence' => 'high',
            ];
        }

        // 3. Explicit owner comparison + deny in-method (above the sink).
        if ($this->hasOwnerCompareDeny($method, $sink->getStartLine())) {
            $evidence[] = [
                'mechanism' => 'owner-compare-deny',
                'detail' => 'owner attribute compared to principal with deny-shape branch',
                'confidence' => 'high',
            ];
        }

        return $evidence;
    }

    /**
     * Authorization evidence (non-ownership but enforcing): can:*
     * middleware, $this->authorize()/authorizeResource, Gate::*, can().
     *
     * @param list<string> $middleware
     * @return list<array{mechanism: string, detail: string, confidence: string}>
     */
    private function authorizationEvidence(
        Node\Stmt\ClassMethod $method,
        Node\Expr\MethodCall|Node\Expr\StaticCall $sink,
        array $middleware
    ): array {
        $evidence = [];
        foreach ($middleware as $item) {
            $kind = MiddlewareTaxonomy::classify($item, []);
            if ($kind === MiddlewareTaxonomy::AUTHORIZATION) {
                $evidence[] = [
                    'mechanism' => 'can-middleware',
                    'detail' => $item,
                    'confidence' => 'high',
                ];
            }
        }
        $stmts = $method->stmts ?? [];
        $sinkLine = $sink->getStartLine();
        $found = $this->finder()->find($stmts, static function (Node $node): bool {
            if ($node instanceof Node\Expr\StaticCall && $node->class instanceof Node\Name) {
                $class = strtolower(ltrim($node->class->toString(), '\\'));
                if (($class === 'gate' || str_ends_with($class, '\\gate')) && $node->name instanceof Node\Identifier) {
                    return in_array(strtolower($node->name->toString()), ['allows', 'authorize', 'check', 'any', 'denies'], true);
                }

                return false;
            }
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array(strtolower($node->name->toString()), ['authorize', 'authorizeresource', 'can', 'cannot'], true);
            }

            return false;
        });
        // The check must precede the sink: authorize-after-delete proves
        // nothing (deny-by-construction patterns like Gate::authorize()
        // throw, so position is the enforcement).
        foreach ($found as $node) {
            if ($node->getStartLine() < $sinkLine) {
                $evidence[] = [
                    'mechanism' => 'policy-gate',
                    'detail' => 'authorize()/Gate::/can() in method',
                    'confidence' => 'high',
                ];
                break;
            }
        }

        return $evidence;
    }

    /**
     * Root expression of a call chain ($user in $user->links()->delete).
     */
    private function chainRoot(Node\Expr $node): ?Node\Expr
    {
        $current = $node;
        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
            $current = $current->var;
        }
        if ($current instanceof Node\Expr\StaticCall) {
            return null;
        }

        return $current instanceof Node\Expr ? $current : null;
    }

    private function isPrincipalRoot(Node\Expr $root): bool
    {
        if ($root instanceof Node\Expr\Variable && is_string($root->name)) {
            return in_array(strtolower($root->name), ['user', 'authuser'], true);
        }
        // Auth::user() / auth()->user() / $request->user().
        if ($root instanceof Node\Expr\StaticCall && $root->class instanceof Node\Name) {
            $class = strtolower(ltrim($root->class->toString(), '\\'));

            return $class === 'auth' || str_ends_with($class, '\\auth');
        }
        if ($root instanceof Node\Expr\FuncCall && $root->name instanceof Node\Name) {
            return strtolower($root->name->toString()) === 'auth';
        }
        if (
            $root instanceof Node\Expr\MethodCall
            && $root->name instanceof Node\Identifier
            && strtolower($root->name->toString()) === 'user'
        ) {
            // $request->user(), auth()->user(), Auth::user().
            if ($root->var instanceof Node\Expr\Variable && is_string($root->var->name)) {
                return $root->var->name === 'request';
            }
            if ($root->var instanceof Node\Expr\FuncCall && $root->var->name instanceof Node\Name) {
                return strtolower($root->var->name->toString()) === 'auth';
            }
            if ($root->var instanceof Node\Expr\StaticCall && $root->var->class instanceof Node\Name) {
                $class = strtolower(ltrim($root->var->class->toString(), '\\'));

                return $class === 'auth' || str_ends_with($class, '\\auth');
            }

            return false;
        }

        return false;
    }

    /**
     * A non-trivial method hop between the principal root and the sink
     * (links(), posts(), ...). can/authorize/allows hops do not open an
     * owned relation.
     */
    private function hasRelationHop(Node\Expr $node, Node\Expr $root): bool
    {
        $current = $node;
        while ($current instanceof Node\Expr\MethodCall || $current instanceof Node\Expr\NullsafeMethodCall) {
            if ($current->name instanceof Node\Identifier) {
                $name = strtolower($current->name->toString());
                if (!in_array($name, [...self::NON_RELATION_METHODS, ...self::SENSITIVE_OPS, 'where', 'find', 'findorfail', 'first', 'get'], true)) {
                    return true;
                }
            }
            if ($current->var === $root) {
                return false;
            }
            $current = $current->var;
            if (!$current instanceof Node\Expr) {
                break;
            }
        }

        return false;
    }

    /**
     * @param list<Node\Expr> $chain
     */
    private function hasOwnerWhere(array $chain, Node\Stmt\ClassMethod $method): bool
    {
        $check = function (Node $node): bool {
            if (
                !$node instanceof Node\Expr\MethodCall
                && !$node instanceof Node\Expr\StaticCall
            ) {
                return false;
            }
            if (!$node->name instanceof Node\Identifier || strtolower($node->name->toString()) !== 'where') {
                return false;
            }
            $col = $node->args[0] ?? null;
            if (!$col instanceof Node\Arg || !$col->value instanceof Node\Scalar\String_) {
                return false;
            }
            // Qualified columns (accounts.user_id) match by suffix —
            // still a literal, no guessing.
            $column = strtolower($col->value->value);
            $owned = false;
            foreach (self::OWNER_COLUMNS as $ownerCol) {
                if ($column === $ownerCol || str_ends_with($column, '.' . $ownerCol)) {
                    $owned = true;
                    break;
                }
            }
            if (!$owned) {
                return false;
            }
            // where(col, val) or where(col, '=', val) — other operators
            // (<>, >, like) are not ownership equality.
            $val = $node->args[1] ?? null;
            if ($val instanceof Node\Arg && $val->value instanceof Node\Scalar\String_) {
                $op = strtolower($val->value->value);
                if ($op !== '=' && $op !== '==') {
                    return false;
                }
                $val = $node->args[2] ?? null;
            }
            if (!$val instanceof Node\Arg) {
                return false;
            }

            return $this->isCurrentUserExpr($val->value);
        };
        foreach ($chain as $node) {
            if ($check($node)) {
                return true;
            }
        }
        foreach ($this->finder()->find($method->stmts ?? [], $check) as $found) {
            if ($found instanceof Node\Expr) {
                return true;
            }
        }

        return false;
    }

    private function isCurrentUserExpr(Node\Expr $expr): bool
    {
        // Auth::id(), auth()->id(), $request->user()->id, Auth::user()->id,
        // $user->id, $authUser->id, $userId-ish variables.
        if ($expr instanceof Node\Expr\StaticCall && $expr->class instanceof Node\Name && $expr->name instanceof Node\Identifier) {
            $class = strtolower(ltrim($expr->class->toString(), '\\'));
            if (($class === 'auth' || str_ends_with($class, '\\auth')) && strtolower($expr->name->toString()) === 'id') {
                return true;
            }
        }
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name && strtolower($expr->name->toString()) === 'auth') {
            return true;
        }
        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            // auth()->user()->id / Auth::user()->id / $user->id. The
            // receiver must be principal-rooted — a bare $link->user_id
            // value is an owner attribute, not the current user.
            if (strtolower($expr->name->toString()) === 'id' && $this->isPrincipalRoot($expr->var)) {
                return true;
            }

            return false;
        }
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            $name = strtolower($expr->name->toString());
            if ($name === 'id' || $name === 'user') {
                return true;
            }
        }
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), ['userid', 'user_id', 'authid', 'auth_id', 'currentuser', 'current_user'], true);
        }

        return false;
    }

    /**
     * Owner comparison + deny: if ($link->user_id != $user->id / Auth::id())
     * with abort(40x)/throw/deny in a branch, positioned above the sink.
     * Bounded to direct method statements (no nested-function leakage).
     */
    private function hasOwnerCompareDeny(Node\Stmt\ClassMethod $method, int $sinkLine): bool
    {
        foreach ($this->finder()->find($method->stmts ?? [], static fn (Node $n): bool => $n instanceof Node\Stmt\If_) as $if) {
            if (!$if instanceof Node\Stmt\If_) {
                continue;
            }
            if ($if->getStartLine() >= $sinkLine) {
                continue;
            }
            if (!$this->isOwnerComparison($if->cond)) {
                continue;
            }
            if ($this->branchDenies($if->stmts) || ($if->else instanceof Node\Stmt\Else_ && $this->branchDenies($if->else->stmts))) {
                return true;
            }
            foreach ($if->elseifs as $elseif) {
                if ($this->branchDenies($elseif->stmts)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isOwnerComparison(Node\Expr $cond): bool
    {
        // Deny-on-INEQUALITY only: if ($link->user_id != Auth::id())
        // abort proves the requester must be the owner. Deny-on-equality
        // (if ($admin->id === $user->id) return) is a self/conflict guard
        // — structurally similar but proves nothing about ownership.
        if ($cond instanceof Node\Expr\BooleanNot) {
            return false;
        }
        if (
            !$cond instanceof Node\Expr\BinaryOp\NotIdentical
            && !$cond instanceof Node\Expr\BinaryOp\NotEqual
        ) {
            return false;
        }

        return $this->isOwnerSide($cond->left) || $this->isOwnerSide($cond->right);
    }

    private function isOwnerSide(Node\Expr $expr): bool
    {
        // $link->user_id / $model->owner_id / ->created_by, or a
        // principal id on the other side (either side counts — the
        // comparison links owner attribute to principal).
        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return in_array(strtolower($expr->name->toString()), [...self::OWNER_COLUMNS, 'id'], true);
        }
        if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
            return strtolower($expr->name->toString()) === 'id';
        }
        if ($expr instanceof Node\Expr\StaticCall && $expr->name instanceof Node\Identifier) {
            return in_array(strtolower($expr->name->toString()), ['id', 'user'], true);
        }
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), ['user', 'authuser', 'userid', 'user_id'], true);
        }

        return false;
    }

    /**
     * @param list<Node\Stmt> $stmts
     */
    private function branchDenies(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            // Return_ ends the flow (method exits before the sink);
            // Throw_ lives under Expr in php-parser 5.
            if ($stmt instanceof Node\Stmt\Return_) {
                return true;
            }
            if (!$stmt instanceof Node\Stmt\Expression) {
                continue;
            }
            $expr = $stmt->expr;
            if ($expr instanceof Node\Expr\Throw_) {
                return true;
            }
            if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
                if (in_array(strtolower($expr->name->toString()), ['abort', 'abort_if', 'abort_unless', 'deny', 'exit', 'die'], true)) {
                    return true;
                }
            }
            if ($expr instanceof Node\Expr\MethodCall && $expr->name instanceof Node\Identifier) {
                if (in_array(strtolower($expr->name->toString()), ['deny', 'abort'], true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
