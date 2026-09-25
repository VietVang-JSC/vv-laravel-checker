<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03 Injection - Command Injection.
 *
 * Assumes: OS command sinks are flagged when an argument is user input (request/input/superglobal) or
 * a tainted variable/expression. Relies on AbstractAnalyzer::isTaintedExpr plus explicit input shape
 * detection; this is a heuristic without cross-function data-flow tracking.
 *
 * Deliberately not flagged: arguments wrapped in escapeshellarg()/escapeshellcmd()
 * (explicit escaping), Symfony Process constructed with an argument array (no shell
 * interpretation), and sinks inside test paths.
 */
final class OwaspCommandInjectionAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_COMMAND_INJECTION';

    private const FUNC_SINKS = ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'];

    private const ESCAPE_FUNCS = ['escapeshellarg', 'escapeshellcmd'];

    /**
     * Functions whose return value is deploy-time determined, never request
     * user input (Laravel path helpers).
     */
    private const SAFE_COMMAND_FUNCS = [
        'base_path', 'storage_path', 'public_path', 'resource_path',
        'database_path', 'app_path', 'config_path', 'lang_path',
    ];

    private const PROCESS_CLASS = 'Symfony\\Component\\Process\\Process';

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

        // Variables assigned a plain argument-array literal, scoped per function, so
        // `new Process($command)` with `$command = [...]` is recognized as shell-free.
        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }
        $scopes = $this->arrayVarScopes($nodes);
        // Variables assigned deploy-time-safe command parts (`$artisan =
        // base_path('artisan')`), so `passthru(PHP_BINARY." $artisan ...")` is
        // recognized as non-user input.
        $safeScopes = $this->safeVarScopes($nodes);

        $issues = [];
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\New_;
        });

        foreach ($calls as $call) {
            if ($call instanceof Node\Expr\FuncCall) {
                if (!$call->name instanceof Node\Name) {
                    continue;
                }
                $fn = $call->name->toString();
                if (!in_array($fn, self::FUNC_SINKS, true)) {
                    continue;
                }

                $arg = $call->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isUserInput($arg->value, $call, $safeScopes, $nodes)) {
                    continue;
                }

                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential command injection: user input flows into %s().', $fn),
                    $file,
                    $call->getStartLine(),
                    Severity::Critical,
                    ['sink' => $fn . '()']
                );
                continue;
            }

            if (
                $call instanceof Node\Expr\New_
                && $call->class instanceof Node\Name
                && in_array($call->class->toString(), [self::PROCESS_CLASS, '\\' . self::PROCESS_CLASS, 'Process'], true)
            ) {
                $first = $call->args[0] ?? null;
                if ($first instanceof Node\Arg && $this->isShellFreeCommand($first->value, $call, $scopes, $nodes)) {
                    continue;
                }
                foreach ($call->args as $arg) {
                    if ($arg instanceof Node\Arg && $this->isUserInput($arg->value, $call, $safeScopes, $nodes)) {
                        $issues[] = $this->makeIssue(
                            self::RULE,
                            'Potential command injection: user input flows into Symfony Process.',
                            $file,
                            $call->getStartLine(),
                            Severity::Critical,
                            ['sink' => 'new Process()']
                        );
                        break;
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $safeScopes
     * @param list<Node> $nodes
     */
    private function isUserInput(Node\Expr $expr, Node $call, array $safeScopes, array $nodes): bool
    {
        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(strtolower($expr->name->toString()), self::ESCAPE_FUNCS, true)
        ) {
            return false;
        }

        if ($this->isSafeCommandExpr($expr, $this->safeVarsVisibleAt($call, $safeScopes))) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\Variable
            && $this->isSafeParam($expr, $call, $nodes, $safeScopes)
        ) {
            return false;
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->isUserInput($part, $call, $safeScopes, $nodes)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isUserInput($expr->left, $call, $safeScopes, $nodes)
                || $this->isUserInput($expr->right, $call, $safeScopes, $nodes);
        }

        if ($this->isTaintedExpr($expr)) {
            return true;
        }

        return false;
    }

    /**
     * A command expression is deploy-time safe when every leaf is a string
     * literal, a constant (PHP_BINARY, DIRECTORY_SEPARATOR, ...), an explicit
     * shell-escaping call, a Laravel path-helper call with safe arguments, or
     * a variable previously assigned such a safe expression in the same scope.
     *
     * @param array<string, true> $known
     */
    private function isSafeCommandExpr(Node\Expr $expr, array $known): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return true;
        }

        if ($expr instanceof Node\Expr\ConstFetch) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return isset($known[$expr->name]);
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
        ) {
            $fn = strtolower($expr->name->toString());
            if (in_array($fn, self::ESCAPE_FUNCS, true)) {
                return true;
            }
            if (in_array($fn, self::SAFE_COMMAND_FUNCS, true)) {
                foreach ($expr->args as $arg) {
                    if ($arg instanceof Node\Arg && !$this->isSafeCommandExpr($arg->value, $known)) {
                        return false;
                    }
                }

                return true;
            }
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isSafeCommandExpr($expr->left, $known)
                && $this->isSafeCommandExpr($expr->right, $known);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && !$this->isSafeCommandExpr($part, $known)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $safeScopes
     * @return array<string, true>
     */
    private function safeVarsVisibleAt(Node $call, array $safeScopes): array
    {
        $callId = spl_object_id($call);
        $vars = [];
        foreach ($safeScopes as $scope) {
            if ($scope['func'] === null) {
                $vars += $scope['vars'];
                continue;
            }
            if (isset($scope['calls'][$callId])) {
                $vars += $scope['vars'];
            }
        }

        return $vars;
    }

    /**
     * Scopes mapping call expressions to the safe-command variables visible in
     * the same function (plus a file-level fallback for top-level code).
     * Assignments are processed in source order so a variable is only known
     * safe after its own safe assignment.
     *
     * @param list<Node> $nodes
     * @return list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}>
     */
    private function safeVarScopes(array $nodes): array
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
                    return $node instanceof Node\Expr\FuncCall
                    || $node instanceof Node\Expr\New_;
                }) as $call
            ) {
                $calls[spl_object_id($call)] = true;
            }
            $scopes[] = ['func' => spl_object_id($func), 'vars' => $this->safeAssignedVars($func), 'calls' => $calls];
        }

        $scopes[] = ['func' => null, 'vars' => $this->safeAssignedVars($nodes), 'calls' => []];

        return $scopes;
    }

    /**
     * @param Node|list<Node> $scope
     * @return array<string, true>
     */
    private function safeAssignedVars(Node|array $scope): array
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
                && $this->isSafeCommandExpr($assign->expr, $vars)
            ) {
                $vars[$assign->var->name] = true;
            }
        }

        foreach ($this->safeForeachVars($scope) as $name => $flag) {
            $vars[$name] = $flag;
        }

        return $vars;
    }

    /**
     * Loop variables iterating over a constant iterable (array literal or
     * class constant, e.g. `foreach (self::SERVICES as $svc)`) are
     * deploy-time values, never request input.
     *
     * @param Node|list<Node> $scope
     * @return array<string, true>
     */
    private function safeForeachVars(Node|array $scope): array
    {
        $vars = [];
        $loops = $this->finder()->find($scope, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Foreach_;
        });
        foreach ($loops as $loop) {
            if (
                $loop instanceof Node\Stmt\Foreach_
                && $loop->valueVar instanceof Node\Expr\Variable
                && is_string($loop->valueVar->name)
                && ($loop->expr instanceof Node\Expr\Array_
                    || $loop->expr instanceof Node\Expr\ClassConstFetch)
            ) {
                $vars[$loop->valueVar->name] = true;
            }
        }

        return $vars;
    }

    /**
     * A command variable that is a parameter of a non-public function is safe
     * when every same-file call site passes a deploy-time-safe argument
     * (e.g. a private helper called only with string literals).
     *
     * @param list<Node> $nodes
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $safeScopes
     */
    private function isSafeParam(
        Node\Expr\Variable $var,
        Node $call,
        array $nodes,
        array $safeScopes
    ): bool {
        if (!is_string($var->name)) {
            return false;
        }

        $func = $this->enclosingFunction($call, $nodes);
        if (!$func instanceof Node\Stmt\ClassMethod || $func->isPublic()) {
            return false;
        }

        $index = null;
        $paramName = null;
        foreach ($func->params as $i => $param) {
            if (!$param instanceof Node\Param || !$param->var instanceof Node\Expr\Variable) {
                continue;
            }
            $candidate = $param->var->name;
            if (!is_string($candidate) || $candidate !== $var->name) {
                continue;
            }
            $index = $i;
            $paramName = $candidate;
            break;
        }
        if ($index === null || $paramName === null) {
            return false;
        }

        $method = $func->name->toString();
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
            $arg = null;
            foreach ($site->args as $i => $candidate) {
                if (!$candidate instanceof Node\Arg) {
                    continue;
                }
                if ($candidate->name instanceof Node\Identifier) {
                    if ($candidate->name->toString() === $paramName) {
                        $arg = $candidate;
                        break;
                    }
                    continue;
                }
                if ($i === $index) {
                    $arg = $candidate;
                    break;
                }
            }
            if (!$arg instanceof Node\Arg) {
                return false;
            }
            if (!$this->isSafeCommandExpr($arg->value, $this->safeVarsVisibleAt($site, $safeScopes))) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}> $scopes
     * @param list<Node> $nodes
     */
    private function isShellFreeCommand(
        Node\Expr $expr,
        Node\Expr\New_ $call,
        array $scopes,
        array $nodes
    ): bool {
        if ($expr instanceof Node\Expr\Array_) {
            return true;
        }

        // Ternary/coalesce whose every branch is shell-free (e.g. picking
        // between two argument arrays) never touches a shell either.
        if ($expr instanceof Node\Expr\Ternary) {
            $branches = [$expr->else];
            if ($expr->if !== null) {
                $branches[] = $expr->if;
            }
            foreach ($branches as $branch) {
                if (!$this->isShellFreeCommand($branch, $call, $scopes, $nodes)) {
                    return false;
                }
            }

            return true;
        }

        if (!$expr instanceof Node\Expr\Variable || !is_string($expr->name)) {
            return false;
        }

        if ($this->isTypedArrayParam($expr->name, $call, $nodes)) {
            return true;
        }

        $callId = spl_object_id($call);
        $inFunc = false;
        foreach ($scopes as $scope) {
            if ($scope['func'] === null) {
                continue;
            }
            if (!isset($scope['calls'][$callId])) {
                continue;
            }
            $inFunc = true;
            if (isset($scope['vars'][$expr->name])) {
                return true;
            }
        }

        if ($inFunc) {
            return false;
        }

        foreach ($scopes as $scope) {
            if ($scope['func'] === null && isset($scope['vars'][$expr->name])) {
                return true;
            }
        }

        return false;
    }

    /**
     * A `new Process($command)` argument is shell-free when the variable is a
     * natively typed `array` parameter (or `@param array/list` documented) of
     * the enclosing function — Symfony Process bypasses the shell for arrays.
     *
     * @param list<Node> $nodes
     */
    private function isTypedArrayParam(string $name, Node\Expr\New_ $call, array $nodes): bool
    {
        $func = $this->enclosingFunction($call, $nodes);
        if ($func === null) {
            return false;
        }

        foreach ($func->params as $param) {
            if (
                !$param instanceof Node\Param
                || !$param->var instanceof Node\Expr\Variable
                || $param->var->name !== $name
            ) {
                continue;
            }
            if ($this->isArrayType($param->type)) {
                return true;
            }

            return $this->hasArrayDocType($param);
        }

        return false;
    }

    /**
     * @param list<Node> $nodes
     */
    private function enclosingFunction(
        Node $call,
        array $nodes
    ): Node\Stmt\ClassMethod|Node\Stmt\Function_|null {
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

    private function isArrayType(Node\Name|Node\Identifier|Node\ComplexType|null $type): bool
    {
        if ($type instanceof Node\Identifier) {
            return strtolower($type->toString()) === 'array';
        }

        if ($type instanceof Node\NullableType) {
            return $this->isArrayType($type->type);
        }

        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            foreach ($type->types as $inner) {
                if ($this->isArrayType($inner)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function hasArrayDocType(Node\Param $param): bool
    {
        $doc = $param->getAttribute('comments');
        if (!is_array($doc)) {
            return false;
        }
        foreach ($doc as $comment) {
            if (!$comment instanceof Node\Stmt\Nop && !$comment instanceof \PhpParser\Comment) {
                continue;
            }
            $text = $comment instanceof \PhpParser\Comment ? $comment->getText() : '';
            if (preg_match('/@param\s+(?:list<[^>]*>|array\b)/i', $text) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scopes mapping `new` expressions to the array-literal variables visible in
     * the same function (plus a file-level fallback for top-level code).
     *
     * @param list<Node> $nodes
     * @return list<array{func: int|null, vars: array<string, true>, calls: array<int, true>}>
     */
    private function arrayVarScopes(array $nodes): array
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
                    return $node instanceof Node\Expr\New_;
                }) as $new
            ) {
                $calls[spl_object_id($new)] = true;
            }
            $scopes[] = ['func' => spl_object_id($func), 'vars' => $this->arrayAssignedVars($func), 'calls' => $calls];
        }

        $scopes[] = ['func' => null, 'vars' => $this->arrayAssignedVars($nodes), 'calls' => []];

        return $scopes;
    }

    /**
     * @param Node|list<Node> $scope
     * @return array<string, true>
     */
    private function arrayAssignedVars(Node|array $scope): array
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
                && $this->isArrayLike($assign->expr)
            ) {
                $vars[$assign->var->name] = true;
            }
        }

        return $vars;
    }

    /**
     * An array literal, or a ternary/coalesce whose every branch is array-like.
     * Either way Symfony Process bypasses the shell.
     */
    private function isArrayLike(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Array_) {
            return true;
        }

        if ($expr instanceof Node\Expr\Ternary) {
            if ($expr->if !== null && !$this->isArrayLike($expr->if)) {
                return false;
            }

            return $this->isArrayLike($expr->else);
        }

        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return $this->isArrayLike($expr->left) && $this->isArrayLike($expr->right);
        }

        return false;
    }
}
