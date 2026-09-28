<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

/**
 * A03 Injection - Server-Side Template Injection.
 *
 * Sinks: view()/Blade()/view()->make(), Blade::render()/compileString(),
 * View::make()/composer()/creator(), and ->make()/renderComponent() on view objects.
 * Assumes: SSTI is reported when a Blade/view rendering call receives a template argument that is not
 * a plain string literal, i.e. a variable, method call, concatenation, or interpolation that could
 * contain user input. Safe dynamic rendering with a whitelisted template key is not tracked.
 *
 * Deliberately not flagged: variables assigned a plain string literal in the same
 * function (`$view = 'backend.page'; view($view)`), which carry no user input;
 * and non-public helpers whose template parameter provably receives only string
 * literals at every same-file call site.
 */
final class OwaspSstiAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_SSTI';

    private const STATIC_SINKS = [
        'Blade::render',
        'Illuminate\\Support\\Facades\\Blade::render',
    ];

    private const METHOD_SINKS = [
        'render', 'renderComponent', 'make', 'compileString', 'composer', 'creator',
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
        $allowLists = $this->allowListedVarScopes($nodes);

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
            if (
                $arg instanceof Node\Expr\Variable
                && is_string($arg->name)
                && $this->isLiteralOnlyParam($arg->name, $call, $nodes, $scopes)
            ) {
                continue;
            }
            if ($this->isLiteralExpression($arg, $call, $scopes)) {
                continue;
            }
            if ($this->isViewRegistry($arg)) {
                continue;
            }
            // in_array($type, ['a', 'b']) allow-list in the same function:
            // the variable provably holds one of the listed literals.
            if ($this->isAllowListed($arg, $call, $allowLists)) {
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

            $isView = $class === 'View' || $class === 'Illuminate\\Support\\Facades\\View' || str_ends_with($class, '\\View');
            if ($isView && in_array($method, ['make', 'composer', 'creator'], true)) {
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
     * Template registries (`$this->views['show']`, `$this->template`) hold
     * framework-resolved view names, not request input — unless rooted at
     * `$request`/`request()`. A bare `$view`/`$template` variable stays
     * flaggable: it may carry anything, and the literal/param rules already
     * cover the provably-safe cases.
     */
    private function isViewRegistry(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return $this->isViewRegistry($expr->var);
        }

        if ($this->rootVariableName($expr) === 'request') {
            return false;
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return in_array(strtolower($expr->name->toString()), ['view', 'views', 'template', 'layout'], true);
        }

        return false;
    }

    /**
     * Variables guarded by an in_array() allow-list of literals in the same
     * function (`if (in_array($type, ['a', 'b'])) { view("x.{$type}"); }`),
     * so they provably hold no user input. The list may be inline or a
     * variable assigned only inline literal arrays in the same function.
     *
     * @param list<Node> $nodes
     * @return array<int, array<string, true>> call id => guarded var names
     */
    private function allowListedVarScopes(array $nodes): array
    {
        $byCall = [];
        $funcs = $this->finder()->find($nodes, function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
        });

        $scopes = [];
        foreach ($funcs as $func) {
            if ($func instanceof Node\Stmt\ClassMethod || $func instanceof Node\Stmt\Function_) {
                $scopes[] = $func;
            }
        }
        $scopes[] = null;

        foreach ($scopes as $scope) {
            $haystack = $scope ?? $nodes;
            $guarded = [];
            $checks = $this->finder()->find($haystack, static function (Node $node): bool {
                return $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && strtolower($node->name->toString()) === 'in_array';
            });
            foreach ($checks as $check) {
                if (!$check instanceof Node\Expr\FuncCall) {
                    continue;
                }
                // Top-level scope only sees top-level guards — a guard inside
                // one function must never silence a sink in another.
                if ($scope === null) {
                    $inside = false;
                    foreach ($funcs as $func) {
                        if (
                            ($func instanceof Node\Stmt\ClassMethod || $func instanceof Node\Stmt\Function_)
                            && $this->nodeContains($func, $check)
                        ) {
                            $inside = true;
                            break;
                        }
                    }
                    if ($inside) {
                        continue;
                    }
                }
                $varArg = $check->args[0] ?? null;
                $listArg = $check->args[1] ?? null;
                if (
                    !$varArg instanceof Node\Arg
                    || !$varArg->value instanceof Node\Expr\Variable
                    || !is_string($varArg->value->name)
                    || !$listArg instanceof Node\Arg
                ) {
                    continue;
                }
                if ($this->isLiteralStringList($listArg->value, $haystack)) {
                    $guarded[$varArg->value->name] = true;
                }
            }
            if ($guarded === []) {
                continue;
            }
            $calls = $this->finder()->find($haystack, static function (Node $node): bool {
                return $node instanceof Node\Expr\StaticCall
                    || $node instanceof Node\Expr\MethodCall
                    || $node instanceof Node\Expr\FuncCall;
            });
            foreach ($calls as $call) {
                // Skip calls that belong to a different function — each
                // function gets its own scope (and top-level guards never
                // leak into functions).
                if ($call instanceof Node) {
                    $nested = false;
                    foreach ($funcs as $func) {
                        if (
                            ($func instanceof Node\Stmt\ClassMethod || $func instanceof Node\Stmt\Function_)
                            && ($scope === null || $func !== $scope)
                            && $this->nodeContains($func, $call)
                        ) {
                            $nested = true;
                            break;
                        }
                    }
                    if ($nested) {
                        continue;
                    }
                }
                $byCall[spl_object_id($call)] = $guarded;
            }
        }

        return $byCall;
    }

    private function nodeContains(Node $haystack, Node $needle): bool
    {
        $target = spl_object_id($needle);
        $found = $this->finder()->find($haystack, static function (Node $node) use ($target): bool {
            return spl_object_id($node) === $target;
        });

        return $found !== [];
    }

    /**
     * An inline array of literal strings/numbers, or a variable assigned
     * only such arrays in the same scope.
     *
     * @param Node|list<Node> $scope
     */
    private function isLiteralStringList(Node\Expr $expr, Node|array $scope): bool
    {
        if ($expr instanceof Node\Expr\Array_) {
            foreach ($expr->items as $item) {
                if (
                    !$item instanceof Node\Expr\ArrayItem
                    || !($item->value instanceof Node\Scalar\String_
                        || $item->value instanceof Node\Scalar\LNumber
                        || $item->value instanceof Node\Scalar\DNumber
                        || $item->value instanceof Node\Expr\ConstFetch
                        || $item->value instanceof Node\Expr\ClassConstFetch)
                ) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            $assigns = $this->finder()->find($scope, static function (Node $node): bool {
                return $node instanceof Node\Expr\Assign;
            });
            $found = false;
            foreach ($assigns as $assign) {
                if (
                    !$assign instanceof Node\Expr\Assign
                    || !$assign->var instanceof Node\Expr\Variable
                    || $assign->var->name !== $expr->name
                ) {
                    continue;
                }
                $found = true;
                if (!$assign->expr instanceof Node\Expr\Array_ || !$this->isLiteralStringList($assign->expr, $scope)) {
                    return false;
                }
            }

            return $found;
        }

        return false;
    }

    /**
     * Every dynamic leaf of the template argument is an allow-listed
     * variable — e.g. view("blade.modals.{$type}") with $type checked by
     * in_array() against literals in the same function.
     *
     * @param array<int, array<string, true>> $allowLists
     */
    private function isAllowListed(Node\Expr $arg, Node $call, array $allowLists): bool
    {
        $guarded = $allowLists[spl_object_id($call)] ?? [];
        if ($guarded === []) {
            return false;
        }
        $names = [];
        foreach (
            $this->finder()->find($arg, static function (Node $node): bool {
                return $node instanceof Node\Expr\Variable;
            }) as $var
        ) {
            if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
                $names[$var->name] = true;
            }
        }
        if ($names === []) {
            return false;
        }
        foreach ($names as $name => $_) {
            if (!isset($guarded[$name])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     */
    private function isLiteralVariable(Node\Expr\Variable $var, Node $call, array $scopes): bool
    {
        if (!is_string($var->name)) {
            return false;
        }

        return isset($this->visibleLiteralVars($call, $scopes)[$var->name]);
    }

    /**
     * A template argument is literal when it (or every leaf, for concat/
     * interpolation/coalesce/ternary) is a string literal or a variable
     * assigned only literals in the visible scope — e.g.
     * `$view = 'front.pos_' . $industry` with `$industry = 2`.
     *
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     */
    private function isLiteralExpression(Node\Expr $expr, Node $call, array $scopes): bool
    {
        return $this->isLiteralValue($expr, $this->visibleLiteralVars($call, $scopes));
    }

    /**
     * @param array<string, true> $known
     */
    private function isLiteralValue(Node\Expr $expr, array $known): bool
    {
        if (
            $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Scalar\LNumber
            || $expr instanceof Node\Scalar\DNumber
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\ConstFetch || $expr instanceof Node\Expr\ClassConstFetch) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return isset($known[$expr->name]);
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return $this->isLiteralValue($expr->var, $known);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isLiteralValue($expr->left, $known)
                && $this->isLiteralValue($expr->right, $known);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->isLiteralValue($part, $known)) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->isLiteralValue($expr->left, $known)
                && $this->isLiteralValue($expr->right, $known);
        }

        if ($expr instanceof Node\Expr\Ternary) {
            if ($expr->if !== null && !$this->isLiteralValue($expr->if, $known)) {
                return false;
            }

            return $this->isLiteralValue($expr->else, $known);
        }

        return false;
    }

    /**
     * Literal variables visible at a call: the enclosing function's set, or
     * the file-level set for top-level code.
     *
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     * @return array<string, true>
     */
    private function visibleLiteralVars(Node $call, array $scopes): array
    {
        $callId = spl_object_id($call);
        foreach ($scopes as $scope) {
            if ($scope['func'] === null) {
                continue;
            }
            if (isset($scope['calls'][$callId])) {
                return $scope['vars'];
            }
        }

        foreach ($scopes as $scope) {
            if ($scope['func'] === null) {
                return $scope['vars'];
            }
        }

        return [];
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
     * A template variable that is a function parameter is safe when the enclosing
     * function is non-public (no external callers with arbitrary input) and every
     * same-file call site passes a string literal (or literal variable) for it.
     *
     * @param list<Node> $nodes
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     */
    private function isLiteralOnlyParam(string $name, Node $call, array $nodes, array $scopes): bool
    {
        $func = $this->enclosingFunction($call, $nodes);
        if ($func === null) {
            return false;
        }
        if ($func instanceof Node\Stmt\ClassMethod && $func->isPublic()) {
            return false;
        }

        $index = null;
        foreach ($func->params as $i => $param) {
            if ($param instanceof Node\Param && $param->var instanceof Node\Expr\Variable && $param->var->name === $name) {
                $index = $i;
                break;
            }
        }
        if ($index === null) {
            return false;
        }

        if ($func instanceof Node\Stmt\ClassMethod) {
            $method = $func->name->toString();
        } else {
            $funcName = $func->name;
            if (!$funcName instanceof Node\Identifier) {
                return false;
            }
            $method = $funcName->toString();
        }

        $callSites = $this->finder()->find($nodes, static function (Node $node) use ($method): bool {
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return $node->name->toString() === $method;
            }
            if ($node instanceof Node\Expr\StaticCall && $node->name instanceof Node\Identifier) {
                return $node->name->toString() === $method;
            }

            return false;
        });

        if ($callSites === []) {
            return false;
        }

        foreach ($callSites as $site) {
            if (!$site instanceof Node\Expr\MethodCall && !$site instanceof Node\Expr\StaticCall) {
                continue;
            }
            if (!$this->callSiteArgIsLiteral($site, $index, $name, $scopes)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<Node> $nodes
     */
    private function enclosingFunction(Node $call, array $nodes): Node\Stmt\ClassMethod|Node\Stmt\Function_|null
    {
        $target = spl_object_id($call);
        $funcs = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
        });

        foreach ($funcs as $func) {
            if (!$func instanceof Node\Stmt\ClassMethod && !$func instanceof Node\Stmt\Function_) {
                continue;
            }
            $found = $this->finder()->find($func, static function (Node $node) use ($target): bool {
                return spl_object_id($node) === $target;
            });
            if ($found !== []) {
                return $func;
            }
        }

        return null;
    }

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     */
    private function callSiteArgIsLiteral(
        Node\Expr\MethodCall|Node\Expr\StaticCall $site,
        int $index,
        string $paramName,
        array $scopes
    ): bool {
        foreach ($site->args as $i => $arg) {
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            if ($arg->name instanceof Node\Identifier) {
                if ($arg->name->toString() !== $paramName) {
                    continue;
                }
            } elseif ($i !== $index) {
                continue;
            }

            return $this->isLiteralString($arg->value)
                || ($arg->value instanceof Node\Expr\Variable && $this->isLiteralVariable($arg->value, $site, $scopes));
        }

        return false;
    }

    /**
     * Variables assigned plain literals — or concatenations/interpolations
     * composed solely of literals and previously-known variables, processed
     * in source order (e.g. `$industry = 2; $view = 'pos_' . $industry`).
     *
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
                && $this->isLiteralValue($assign->expr, $vars)
            ) {
                $vars[$assign->var->name] = true;
            }
        }

        return $vars;
    }
}
