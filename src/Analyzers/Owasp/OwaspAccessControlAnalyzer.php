<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Semantic\AccessDecision;
use Rampart\QualityChecker\Semantic\FormRequestIndex;
use Rampart\QualityChecker\Semantic\LaravelSemanticIndex;
use Rampart\QualityChecker\Semantic\MiddlewareEvidence;
use Rampart\QualityChecker\Semantic\MiddlewareInspector;
use Rampart\QualityChecker\Semantic\MiddlewareRegistry;
use Rampart\QualityChecker\Semantic\MiddlewareTaxonomy;
use Rampart\QualityChecker\Semantic\RouteNode;

/**
 * A01 Broken Access Control.
 *
 * Decision flow per mutating controller action:
 *
 *   RouteNode (middleware inherited through groups/providers)
 *       │
 *       ▼
 *   Controller action (+ local authorization evidence:
 *   authorize()/Gate/FormRequest/constructor context)
 *       │
 *       ▼
 *   Access-Control Decision: PROTECTED | REVIEW | EXPOSED | UNKNOWN
 *
 * Authentication is not authorization: an `auth`/`auth:api`/token-guard
 * stack proves identity but never permission, so auth-only routes yield
 * REVIEW findings (medium confidence) instead of being suppressed.
 * Only ability checks (`can:*`, `permission:*`, `role:*`, configured
 * `extra_middleware`) or local authorization evidence yield PROTECTED.
 * Custom middleware (`admin`, `owner`, `signed`, ...) is unverifiable
 * and lands in REVIEW — recorded as evidence, never assumed to
 * authorize. `throttle`/`guest`/`web`/`api` carry no access meaning.
 *
 * One action reached by several routes keeps one decision per route
 * context — contexts are never merged into a single "has auth" flag.
 * The worst context wins and the finding cites the offending route
 * (methods, URI, middleware stack) in its metadata.
 */
final class OwaspAccessControlAnalyzer extends AbstractAnalyzer
{
    public const RULE = 'OWASP_BROKEN_ACCESS_CONTROL';

    private const MUTATING_METHODS = [
        'store', 'update', 'delete', 'destroy', 'restore', 'forceDelete',
    ];

    private const MUTATING_CALLS = ['save', 'delete', 'update', 'create', 'insert', 'upsert', 'destroy'];

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
        $scan = $this->sharedScanContext();
        // PERF-EVAL-2 phase split: semantic index construction is timed
        // separately from per-file analysis (both roll up into this
        // analyzer's wall time).
        Profiler::begin('semantic-index');
        $index = $this->routeMiddleware ? (new LaravelSemanticIndex($scan))->build($files) : null;
        $registry = null;
        if ($this->routeMiddleware) {
            $registry = new MiddlewareRegistry();
            $registry->setScanContext($scan);
            $registry->build($files);
        }
        $formRequests = new FormRequestIndex();
        $formRequests->setScanContext($scan);
        $formRequests->build($files);
        Profiler::end('semantic-index');

        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $index, $registry, $formRequests) as $issue) {
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
     * Evidence comes from FormRequestIndex: ability checks (can/Gate)
     * are strong, other non-trivial bodies stay protective for backward
     * compatibility, literal `true` never is.
     *
     * @param array<string, string> $uses
     */
    private function hasAuthorizingFormRequest(
        Node\Stmt\ClassMethod $method,
        array $uses,
        ?string $namespace,
        FormRequestIndex $formRequests
    ): bool {
        foreach ($method->params as $param) {
            if (!$param->type instanceof Node\Name) {
                continue;
            }
            $resolved = strtolower($this->resolveParam($param->type->toString(), $uses, $namespace));
            if ($formRequests->authorizationEvidence($resolved) !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, string> $uses
     */
    private function resolveParam(string $type, array $uses, ?string $namespace): string
    {
        if (str_starts_with($type, '\\')) {
            return ltrim($type, '\\');
        }
        if (!str_contains($type, '\\') && isset($uses[strtolower($type)])) {
            return $uses[strtolower($type)];
        }
        $pos = strpos($type, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($type, 0, $pos));
            if (isset($uses[$first])) {
                return $uses[$first] . substr($type, $pos);
            }
        }

        return $namespace !== null ? $namespace . '\\' . $type : $type;
    }

    /**
     * @return list<Issue>
     */
    private function analyzeFile(
        string $file,
        ?LaravelSemanticIndex $index,
        ?MiddlewareRegistry $registry,
        FormRequestIndex $formRequests
    ): array {
        $ast = $this->sharedAst($file);
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
            foreach ($this->analyzeController($class, $file, $index, $registry, $namespace, $uses, $formRequests) as $issue) {
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
     * @param array<string, string> $uses
     * @return Issue[]
     */
    private function analyzeController(
        Node\Stmt\Class_ $class,
        string $file,
        ?LaravelSemanticIndex $index,
        ?MiddlewareRegistry $registry,
        ?string $namespace,
        array $uses = [],
        ?FormRequestIndex $formRequests = null
    ): array {
        $issues = [];
        $hasAuthContext = $this->classHasAuthContext($class);
        $controller = $class->name instanceof Node\Identifier
            ? ($namespace !== null ? $namespace . '\\' . $class->name->toString() : $class->name->toString())
            : '';

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
            // Strong local evidence suppresses regardless of routes.
            $requestAuth = $formRequests !== null
                && $this->hasAuthorizingFormRequest($stmt, $uses, $namespace, $formRequests);
            if (
                $hasAuthContext
                || $this->methodHasAuth($stmt)
                || $requestAuth
            ) {
                continue;
            }

            $decision = $this->decide($controller, $methodName, $index, $registry);
            if ($decision->status === AccessDecision::PROTECTED) {
                continue;
            }

            $issues[] = $this->decisionIssue($controller, $methodName, $decision, $file, $stmt->getStartLine());
        }

        return $issues;
    }

    /**
     * Worst-context-wins across every route answering the action.
     * Contexts are never merged: one public route among protected ones
     * still yields an EXPOSED finding citing that route.
     */
    private function decide(
        string $controller,
        string $method,
        ?LaravelSemanticIndex $index,
        ?MiddlewareRegistry $registry
    ): AccessDecision {
        if ($index === null) {
            return new AccessDecision(AccessDecision::UNKNOWN, null, [], []);
        }
        $routes = $index->routesForAction($controller, $method);
        if ($routes === []) {
            return new AccessDecision(AccessDecision::UNKNOWN, null, [], []);
        }

        $inspector = new MiddlewareInspector();
        $inspector->setScanContext($this->sharedScanContext());
        /** @var array<string, MiddlewareEvidence|null> $inspected */
        $inspected = [];
        $decisions = [];
        foreach ($routes as $route) {
            $decisions[] = $this->decideRoute($route, $registry, $inspector, $inspected);
        }
        foreach ($decisions as $candidate) {
            if ($candidate->status === AccessDecision::EXPOSED) {
                return $candidate;
            }
        }
        foreach ($decisions as $candidate) {
            if ($candidate->status === AccessDecision::REVIEW) {
                return $candidate;
            }
        }

        return $decisions[0];
    }

    /**
     * @param array<string, MiddlewareEvidence|null> $inspected memoized per run
     */
    private function decideRoute(
        RouteNode $route,
        ?MiddlewareRegistry $registry,
        MiddlewareInspector $inspector,
        array &$inspected
    ): AccessDecision {
        $evidence = [];
        $resolutions = [];
        $authenticated = false;
        $gated = false;
        foreach ($route->middleware as $middleware) {
            $kind = MiddlewareTaxonomy::classify($middleware, $this->extraMiddleware);
            if ($kind === MiddlewareTaxonomy::AUTHORIZATION) {
                $evidence[] = $middleware;
                continue;
            }
            if ($kind === MiddlewareTaxonomy::AUTHENTICATION) {
                $authenticated = true;
                continue;
            }
            if ($kind !== MiddlewareTaxonomy::GATE) {
                continue;
            }
            $gated = true;
            $alias = strtolower(trim(explode(':', $middleware, 2)[0]));
            $routeAbility = $this->routeAbility($middleware);
            $resolution = $this->resolveMiddleware($alias, $routeAbility, $registry, $inspector, $inspected);
            if ($resolution['evidence'] instanceof MiddlewareEvidence) {
                $evidence[] = $resolution['evidence']->toArray();
                continue;
            }
            // Resolved but not understood (or not registered at all):
            // keep the trail for human review instead of guessing.
            if ($resolution['trail'] !== null) {
                $resolutions[] = $resolution['trail'];
            }
        }

        $routeRef = [
            'methods' => $route->methods,
            'uri' => $route->uri,
            'file' => $route->file,
            'line' => $route->line,
        ];
        if ($evidence !== []) {
            return new AccessDecision(AccessDecision::PROTECTED, $routeRef, $route->middleware, $evidence, []);
        }
        if ($authenticated || $gated) {
            return new AccessDecision(AccessDecision::REVIEW, $routeRef, $route->middleware, [], $resolutions);
        }

        return new AccessDecision(AccessDecision::EXPOSED, $routeRef, $route->middleware, [], []);
    }

    private function routeAbility(string $middleware): ?string
    {
        $parts = explode(':', $middleware, 2);
        $ability = trim($parts[1] ?? '');

        return $ability === '' ? null : $ability;
    }

    /**
     * Tier 1 + tier 2 for one gate middleware: alias → class → handle()
     * evidence. Inspector outcomes are memoized per alias within the run.
     *
     * @param array<string, MiddlewareEvidence|null> $inspected
     * @return array{evidence: MiddlewareEvidence|null, trail: array{alias: string, class: string|null, method: string|null, source: string|null, mechanism: string}|null}
     */
    private function resolveMiddleware(
        string $alias,
        ?string $routeAbility,
        ?MiddlewareRegistry $registry,
        MiddlewareInspector $inspector,
        array &$inspected
    ): array {
        $registration = $registry?->resolve($alias);
        if ($registration === null || $registry === null) {
            return [
                'evidence' => null,
                'trail' => [
                    'alias' => $alias,
                    'class' => $registration['class'] ?? null,
                    'method' => null,
                    'source' => null,
                    'mechanism' => 'unregistered',
                ],
            ];
        }
        if (!array_key_exists($alias, $inspected)) {
            $classFile = $registry->classFile($registration['class']);
            $inspected[$alias] = $classFile === null
                ? null
                : $inspector->inspect($classFile, $registration['class'], $alias, $routeAbility);
        }
        $evidence = $inspected[$alias];
        if ($evidence instanceof MiddlewareEvidence) {
            return ['evidence' => $evidence, 'trail' => null];
        }

        return [
            'evidence' => null,
            'trail' => [
                'alias' => $alias,
                'class' => $registration['class'],
                'method' => 'handle',
                'source' => $registration['file'] . ':' . ($registration['line'] ?? 0),
                'mechanism' => 'unrecognized',
            ],
        ];
    }

    private function decisionIssue(
        string $controller,
        string $method,
        AccessDecision $decision,
        string $file,
        int $line
    ): Issue {
        $metadata = [
            'controller' => $controller,
            'action' => $method,
            'route' => $decision->route,
            'middleware' => $decision->middleware,
            'authorization_evidence' => $decision->authorizationEvidence,
            'middleware_resolution' => $decision->middlewareResolution,
            'semantic_status' => $decision->status,
        ];
        if ($decision->status === AccessDecision::REVIEW) {
            return $this->makeIssue(
                self::RULE,
                sprintf(
                    'Mutating method %s() is authenticated but has no visible authorization check.',
                    $method
                ),
                $file,
                $line,
                Severity::Error,
                array_merge($metadata, ['method' => $method]),
                Confidence::Medium
            );
        }

        return $this->makeIssue(
            self::RULE,
            sprintf('Mutating method %s() has no visible authorization check.', $method),
            $file,
            $line,
            Severity::Error,
            array_merge($metadata, ['method' => $method])
        );
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

    /**
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
}
