<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Analysis\AssignmentMap;
use Rampart\QualityChecker\Analysis\FlowTrace;
use Rampart\QualityChecker\Analysis\ScopeResolver;
use Rampart\QualityChecker\Analysis\StructuralFactIndex;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

/**
 * A01 Open Redirect.
 *
 * Sinks: redirect($target), redirect()->away($t), redirect()->to($t),
 * redirect()->intended($default), the Redirect::away()/to()/intended()
 * facades, and response(...)->header('Location', $t).
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

    /**
     * Method names that by construction return a provider-hosted signed URL,
     * never an attacker-steered host. `getUrl()` is deliberately excluded —
     * generic URL builders can return anything.
     */
    private const SIGNED_URL_METHODS = ['temporaryurl', 'presignedurl', 'getpresignedurl', 'temporary_url', 'presigned_url', 'getauthorizationurl'];

    private ?ScopeResolver $scopes = null;

    private ?AssignmentMap $assignments = null;

    private ?StructuralFactIndex $facts = null;

    /**
     * Shared structural facts for this run (one indexing traversal per
     * file). Replaces the per-sink full-tree re-traversals; scope
     * questions below still go through ScopeResolver/AssignmentMap.
     */
    private function facts(): StructuralFactIndex
    {
        if ($this->facts === null) {
            $this->facts = new StructuralFactIndex();
            $this->facts->setScanContext($this->sharedScanContext());
        }

        return $this->facts;
    }

    /**
     * Scope id via parent links (outermost-wins): identical to
     * ScopeResolver::funcId for real code (nested named functions
     * resolve to the outermost container, matching traversal-order
     * first-containment). O(depth), no tree walk.
     */
    private function funcIdViaParents(Node $node): int
    {
        $id = 0;
        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
            $id = spl_object_id($node);
        }
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if (
                $parent instanceof Node\Stmt\ClassMethod
                || $parent instanceof Node\Stmt\Function_
            ) {
                $id = spl_object_id($parent);
            }
            $current = $parent;
        }

        return $id;
    }

    private function scopes(): ScopeResolver
    {
        if ($this->scopes === null) {
            $this->scopes = new ScopeResolver($this->finder());
        }

        return $this->scopes;
    }

    private function assignments(): AssignmentMap
    {
        if ($this->assignments === null) {
            $this->assignments = new AssignmentMap($this->finder(), $this->scopes());
        }

        return $this->assignments;
    }

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
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }
        $guarded = $this->guardSanitizedVars($file, $nodes, []);

        $issues = [];
        // Structural facts: all call expressions in one indexed pass,
        // replacing the per-file full-tree find (resolveSink filters).
        $calls = $this->facts()->calls($file, $nodes);

        foreach ($calls as $call) {
            $sink = $this->resolveSink($call);
            if ($sink === null) {
                continue;
            }

            [$label, $target] = $sink;
            if ($target === null) {
                continue;
            }
            // Data-flow v0.1: only assignments in the same scope, above the
            // sink line, are visible — a literal assigned later, or in
            // another function, never silences this sink.
            $maps = $this->visibleVarMaps($nodes, $call);
            $known = $maps['safe'];
            $pinned = $maps['pinned'];
            $literals = $maps['literals'];
            if ($this->isSafeTarget($target, $known)) {
                continue;
            }
            // Host-pinned lead: route('home').$path or signed storage URLs
            // keep the host even when the tail is dynamic.
            if ($this->hasPinnedHostLead($target, $known, $pinned, $literals)) {
                continue;
            }
            // Sanitizer-guarded: str_starts_with() gate with reassignment
            // or early enforcement in the same function, above the sink.
            if ($this->isGuardSanitized($target, $call, $nodes, $guarded)) {
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
                ['sink' => $label, 'flow' => $this->traceFor($target, $call, $nodes, $label)->toMetadata()],
                $this->isDirectTarget($target) ? Confidence::High : Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * Minimal explainability trace for a flagged finding: source →
     * propagation → sink. Only straight-line assignments visible at the
     * sink are listed as propagation steps.
     *
     * @param list<Node> $nodes
     */
    private function traceFor(Node\Expr $target, Node $call, array $nodes, string $label): FlowTrace
    {
        $trace = new FlowTrace();
        $trace->source(
            $this->readsRequest($target) ? 'request input' : 'dynamic value',
            $target->getStartLine()
        );

        $sinkLine = $call->getStartLine();
        $funcId = $this->scopes()->funcId($call, $nodes);
        foreach ($this->assignments()->visible($nodes, $funcId, $sinkLine) as $assign) {
            if (!$assign->var instanceof Node\Expr\Variable || !is_string($assign->var->name)) {
                continue;
            }
            if (!$this->targetUsesVar($target, $assign->var->name)) {
                continue;
            }
            $trace->propagate('$' . $assign->var->name . ' assigned', $assign->getStartLine());
        }

        return $trace->sink($label, $sinkLine);
    }

    private function targetUsesVar(Node\Expr $target, string $name): bool
    {
        $found = $this->finder()->find($target, static function (Node $node) use ($name): bool {
            return $node instanceof Node\Expr\Variable && $node->name === $name;
        });

        return $found !== [];
    }

    /**
     * header('Location: ...') performs a redirect. Only Location headers count —
     * other headers (Content-Type, X-...) cannot redirect.
     */
    private function isLocationHeader(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return (bool) preg_match('/^\s*location\s*:/i', $expr->value);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isLocationHeader($expr->left) || $this->containsLocationPrefix($expr);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Scalar\String_ && preg_match('/location\s*:/i', $part->value) === 1) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    private function containsLocationPrefix(Node\Expr\BinaryOp\Concat $expr): bool
    {
        $left = $expr->left;
        while ($left instanceof Node\Expr\BinaryOp\Concat) {
            $left = $left->left;
        }

        return $left instanceof Node\Scalar\String_
            && preg_match('/^\s*location\s*:/i', $left->value) === 1;
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
                if (strtolower($node->name->toString()) === 'header') {
                    $arg = $node->args[0] ?? null;
                    $target = $arg instanceof Node\Arg ? $arg->value : null;
                    if ($target !== null && $this->isLocationHeader($target)) {
                        return ['header()', $target];
                    }
                }

                return null;
            }
            $arg = $node->args[0] ?? null;

            return ['redirect()', $arg instanceof Node\Arg ? $arg->value : null];
        }

        if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $method = strtolower($node->name->toString());
            // response('', 302)->header('Location', $url): only the Location
            // header performs a redirect — other headers cannot redirect.
            if ($method === 'header' && $this->isResponseReceiver($node->var)) {
                $nameArg = $node->args[0] ?? null;
                $targetArg = $node->args[1] ?? null;
                $name = $nameArg instanceof Node\Arg ? $nameArg->value : null;
                $target = $targetArg instanceof Node\Arg ? $targetArg->value : null;
                if ($name instanceof Node\Scalar\String_ && strtolower($name->value) === 'location' && $target !== null) {
                    return ["->header('Location')", $target];
                }

                return null;
            }
            if ($method === 'route' || $method === 'back') {
                return null;
            }
            if ($method !== 'away' && $method !== 'to' && $method !== 'intended') {
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
            if ($method !== 'away' && $method !== 'to' && $method !== 'intended') {
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

    /**
     * Receiver of a ->header() call that yields an HTTP response:
     * response(...)/redirect(...) helpers (possibly chained).
     */
    private function isResponseReceiver(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return in_array(strtolower($expr->name->toString()), ['response', 'redirect'], true);
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isResponseReceiver($expr->var);
        }

        return false;
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
     * Data-flow v0.1 variable maps for one sink: only STRAIGHT-LINE
     * assignments (never inside if/try/loops/closures) in the same scope,
     * above the sink line, are visible, accumulated in source order. A
     * conditional reassignment (`if (...) { $v = '/'; }`) never silences —
     * one path may keep the tainted value; use a guard gate for those.
     *
     * @param list<Node> $nodes
     * @return array{safe: array<string, true>, pinned: array<string, true>, literals: array<string, string>}
     */
    private function visibleVarMaps(array $nodes, Node $call): array
    {
        $sinkLine = $call->getStartLine();
        $funcId = $this->funcIdViaParents($call);

        $safe = [];
        $pinned = [];
        $literals = [];
        foreach ($this->assignments()->visible($nodes, $funcId, $sinkLine) as $assign) {
            if (!$assign->var instanceof Node\Expr\Variable) {
                continue;
            }
            $name = $assign->var->name;
            if (!is_string($name)) {
                continue;
            }
            if ($assign->expr instanceof Node\Scalar\String_) {
                $literals[$name] = $assign->expr->value;
            }
            if ($this->isSafeTarget($assign->expr, $safe)) {
                $safe[$name] = true;
            }
            if ($this->isHostPinned($assign->expr, $safe, $pinned)) {
                $pinned[$name] = true;
            }
        }

        return ['safe' => $safe, 'pinned' => $pinned, 'literals' => $literals];
    }

    /**
     * True when the expression's host cannot be steered: a route()/url()/
     * config()/env() call, a signed-URL method, a pinned variable, or a
     * concatenation whose left side is pinned.
     *
     * @param array<string, true> $known
     * @param array<string, true> $pinned
     */
    private function isHostPinned(Node\Expr $expr, array $known, array $pinned): bool
    {
        // A leading literal with its own host pins the redirect:
        // 'https://oauth.host/authorize?' . $query cannot steer off-site.
        if ($expr instanceof Node\Scalar\String_) {
            return $this->hasFixedHostPrefix($expr->value);
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), self::SAFE_FUNCS, true)
        ) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), self::SIGNED_URL_METHODS, true)
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return isset($pinned[$expr->name]);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isHostPinned($expr->left, $known, $pinned);
        }

        return false;
    }

    /**
     * A concatenation/interpolation whose leading part pins the host
     * (`route('index') . $from`) cannot redirect off-site no matter how
     * dynamic the tail is. Same for sprintf() with a fixed-host format
     * (`sprintf('https://oauth.host/authorize?%s', $query)`).
     *
     * @param array<string, true> $known
     * @param array<string, true> $pinned
     * @param array<string, string> $literals
     */
    private function hasPinnedHostLead(Node\Expr $expr, array $known, array $pinned, array $literals): bool
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isHostPinned($expr->left, $known, $pinned);
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->toString()) === 'sprintf'
        ) {
            $format = $expr->args[0] ?? null;
            if (!$format instanceof Node\Arg) {
                return false;
            }
            if ($format->value instanceof Node\Scalar\String_) {
                return $this->hasFixedHostPrefix($format->value->value);
            }
            if (
                $format->value instanceof Node\Expr\Variable
                && is_string($format->value->name)
                && isset($literals[$format->value->name])
            ) {
                return $this->hasFixedHostPrefix($literals[$format->value->name]);
            }

            return false;
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\InterpolatedStringPart) {
                    if ($part->value !== '') {
                        return false;
                    }
                    continue;
                }
                return $this->isHostPinned($part, $known, $pinned);
            }
        }

        return false;
    }

    private function hasFixedHostPrefix(string $value): bool
    {
        return preg_match('#^https?://[^/$\s]+/#i', $value) === 1;
    }

    /**
     * Variables sanitized by a str_starts_with() prefix gate in the same
     * function, effective for sinks below the gate:
     *   if (!str_starts_with($v, $safe)) { $v = '/'; }
     *   if (!str_starts_with($v, $safe)) { throw/abort/return ...; }
     * Either way every path past the gate leaves $v on-host. Only the
     * prefix form counts — suffix/contains checks cannot pin a host.
     * Ternary reassignment (`$v = str_starts_with($v, $s) ? $v : '/';`)
     * counts as well.
     *
     * @param list<Node> $nodes
     * @param array<string, true> $known
     * @return array<int, array<string, int>> func id => var name => guard line
     */
    /**
     * @param list<Node> $nodes
     * @param array<string, true> $known
     * @return array<int, array<string, int>>
     */
    private function guardSanitizedVars(string $file, array $nodes, array $known): array
    {
        $guarded = [];

        // Scope order mirrors the old implementation: functions in
        // traversal order, top-level scope 0 last (rememberGuard takes
        // the minimum line, so order is stability-only). null = whole
        // file (top-level scope: the old code searched $nodes, then
        // kept only funcId 0).
        $scopes = [];
        foreach ($this->facts()->functions($file, $nodes) as $func) {
            $scopes[spl_object_id($func)] = $func;
        }
        $scopes[0] = null;

        foreach ($scopes as $funcId => $scope) {
            foreach ($this->facts()->assignsAndIfs($file, $nodes) as $node) {
                // Same filter as the old per-scope find: only nodes
                // inside this scope's subtree, in this scope's funcId.
                if ($scope !== null && !$this->isWithin($node, $scope)) {
                    continue;
                }
                if ($this->funcIdViaParents($node) !== $funcId) {
                    continue;
                }
                if ($node instanceof Node\Expr\Assign) {
                    $this->collectTernaryGuard($node, $funcId, $known, $guarded);
                    continue;
                }
                if ($node instanceof Node\Stmt\If_) {
                    $this->collectIfGuard($node, $funcId, $known, $guarded);
                }
            }
        }

        return $guarded;
    }

    /**
     * Subtree containment via parent links (O(depth), no tree walk).
     */
    private function isWithin(Node $node, Node $ancestor): bool
    {
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if ($parent === $ancestor) {
                return true;
            }
            $current = $parent;
        }

        return false;
    }

    /**
     * @param array<string, true> $known
     * @param array<int, array<string, int>> $guarded
     */
    private function collectTernaryGuard(Node\Expr\Assign $assign, int $funcId, array $known, array &$guarded): void
    {
        if (
            !$assign->var instanceof Node\Expr\Variable
            || !is_string($assign->var->name)
            || !$assign->expr instanceof Node\Expr\Ternary
            || $assign->expr->if === null
        ) {
            return;
        }
        $guardedVar = $this->prefixGuardedVar($assign->expr->cond, $known);
        if ($guardedVar === null || $guardedVar !== $assign->var->name) {
            return;
        }
        if (!$this->isSafeTarget($assign->expr->else, $known)) {
            return;
        }
        $line = $assign->getStartLine();
        $this->rememberGuard($guarded, $funcId, $guardedVar, $line);
    }

    /**
     * @param array<string, true> $known
     * @param array<int, array<string, int>> $guarded
     */
    private function collectIfGuard(Node\Stmt\If_ $if, int $funcId, array $known, array &$guarded): void
    {
        $guardedVar = $this->negatedPrefixGuardedVar($if->cond, $known);
        if ($guardedVar === null) {
            return;
        }
        $line = $if->getStartLine();
        foreach ($if->stmts as $stmt) {
            if ($this->stmtReassignsSafe($stmt, $guardedVar, $known) || $this->isEnforcingExit($stmt)) {
                $this->rememberGuard($guarded, $funcId, $guardedVar, $line);

                return;
            }
        }
        if ($if->else instanceof Node\Stmt\Else_ && $this->branchReassignsSafe($if->else->stmts, $guardedVar, $known)) {
            $this->rememberGuard($guarded, $funcId, $guardedVar, $line);
        }
    }

    /**
     * @param array<int, array<string, int>> $guarded
     */
    private function rememberGuard(array &$guarded, int $funcId, string $var, int $line): void
    {
        if (!isset($guarded[$funcId][$var]) || $line < $guarded[$funcId][$var]) {
            $guarded[$funcId][$var] = $line;
        }
    }

    /**
     * str_starts_with($var, $safe-prefix) with a safe prefix expression in
     * ternary position. Returns the guarded variable name or null.
     *
     * @param array<string, true> $known
     */
    private function prefixGuardedVar(Node\Expr $cond, array $known): ?string
    {
        if (
            !$cond instanceof Node\Expr\FuncCall
            || !$cond->name instanceof Node\Name
            || strtolower($cond->name->toString()) !== 'str_starts_with'
        ) {
            return null;
        }
        $varArg = $cond->args[0] ?? null;
        $prefixArg = $cond->args[1] ?? null;
        if (
            !$varArg instanceof Node\Arg
            || !$varArg->value instanceof Node\Expr\Variable
            || !is_string($varArg->value->name)
            || !$prefixArg instanceof Node\Arg
            || !$this->isSafeTarget($prefixArg->value, $known)
        ) {
            return null;
        }

        return $varArg->value->name;
    }

    /**
     * !str_starts_with($var, $safe-prefix): the negated gate whose branch
     * reassigns or exits.
     *
     * @param array<string, true> $known
     */
    private function negatedPrefixGuardedVar(Node\Expr $cond, array $known): ?string
    {
        if (
            !$cond instanceof Node\Expr\BooleanNot
            || !$cond->expr instanceof Node\Expr\FuncCall
        ) {
            return null;
        }

        return $this->prefixGuardedVar($cond->expr, $known);
    }

    /**
     * @param array<string, true> $known
     */
    private function stmtReassignsSafe(Node\Stmt $stmt, string $var, array $known): bool
    {
        if (!$stmt instanceof Node\Stmt\Expression || !$stmt->expr instanceof Node\Expr\Assign) {
            return false;
        }
        $assign = $stmt->expr;

        return $assign->var instanceof Node\Expr\Variable
            && $assign->var->name === $var
            && $this->isSafeTarget($assign->expr, $known);
    }

    /**
     * @param list<Node\Stmt> $stmts
     * @param array<string, true> $known
     */
    private function branchReassignsSafe(array $stmts, string $var, array $known): bool
    {
        foreach ($stmts as $stmt) {
            if ($this->stmtReassignsSafe($stmt, $var, $known)) {
                return true;
            }
        }

        return false;
    }

    private function isEnforcingExit(Node\Stmt $stmt): bool
    {
        // Throw_ lives under Expr in php-parser 5; Return_ ends the flow.
        // break/continue are deliberately excluded: breaking out of a loop
        // still reaches later sinks with the tainted value.
        if (!$stmt instanceof Node\Stmt\Expression) {
            return $stmt instanceof Node\Stmt\Return_;
        }
        $expr = $stmt->expr;
        if ($expr instanceof Node\Expr\Throw_) {
            return true;
        }

        return $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), ['abort', 'abort_if', 'abort_unless', 'exit', 'die'], true);
    }

    /**
     * Every dynamic leaf of the target is a guarded variable visible at the
     * sink (guard above the sink line, same function scope).
     *
     * @param list<Node> $nodes
     * @param array<int, array<string, int>> $guarded
     */
    private function isGuardSanitized(Node\Expr $target, Node $call, array $nodes, array $guarded): bool
    {
        $funcId = $this->funcIdViaParents($call);
        $vars = [];
        foreach (
            $this->finder()->find($target, static function (Node $node): bool {
                return $node instanceof Node\Expr\Variable;
            }) as $var
        ) {
            if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
                $vars[$var->name] = true;
            }
        }
        if ($vars === []) {
            return false;
        }
        $sinkLine = $call->getStartLine();
        foreach ($vars as $name => $_) {
            $guardLine = $guarded[$funcId][$name] ?? $guarded[0][$name] ?? null;
            if ($guardLine === null || $sinkLine <= $guardLine) {
                return false;
            }
        }

        return true;
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
            // route() pins the application host, but url($dynamic) is NOT
            // safe: UrlGenerator returns already-valid URLs unchanged, so a
            // dynamic argument can still steer off-site.
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

        // $request->url() with no arguments returns the current request URL
        // — the host is the application host by construction. A ->url()
        // WITH arguments is an unknown builder call and stays flaggable.
        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'url'
            && $expr->args === []
        ) {
            return true;
        }

        // SDK-signed storage URLs (Storage::disk()->temporaryUrl(...),
        // $storage->getPresignedUrl(...)): the host is the configured
        // storage provider, never attacker-controlled.
        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), self::SIGNED_URL_METHODS, true)
        ) {
            return true;
        }

        // *Safe* naming convention (getSafeUrl(), getSafePreviousUrl(), ...):
        // the callee asserts a validated URL, mirroring the *Html/*Sanitized
        // convention for pre-rendered Blade output. A lying name would hide a
        // finding — accepted trade-off, documented.
        if (
            ($expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall)
            && $expr->name instanceof Node\Identifier
            && stripos($expr->name->toString(), 'safe') !== false
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
