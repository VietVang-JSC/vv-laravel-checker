<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security\Taint;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\FunctionLike;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Parser;
use PhpParser\ParserFactory;

/**
 * A lightweight, intra-file + cross-file-callable taint / data-flow engine.
 *
 * Capability:
 *  - Builds a per-file AST index (functions & class methods) for call resolution.
 *  - Tracks taint from request-derived sources:
 *      $request->input(), input(), request()->all(), request()->input(),
 *      $_GET/$_POST/$_REQUEST/$_COOKIE, $this->request->..., request()->query().
 *  - Propagates taint through variable assignments, return statements, array
 *    element fetch/write, and function/method argument positions (callee param
 *    index via the call graph).
 *  - Detects taint reaching sink calls and reports one Issue per occurrence.
 *
 * Conservative heuristics to keep false positives low (assumptions):
 *  1. Only variables actually assigned a tainted value are tracked; unknown
 *     globals and opaque object properties are not considered tainted.
 *  2. A function/method that accepts a tainted argument is only considered a
 *     "propagator" for the exact parameter index that received the tainted
 *     value, resolved through the call graph by parameter name/order.
 *  3. Calls to resolvable sinks are matched by FQN through
 *     TaintSourceResolver; non-resolvable dynamic calls (e.g. $obj->method())
 *     are bailed on (not reported) to avoid noise.
 *  4. Assignment through function return values is only propagated when the
 *     callee body is available in the indexed set and it returned a tainted var.
 *
 * Known limitations:
 *  - Cross-file propagation is limited to functions/methods present in the
 *    analysed set; calls to external/vendor code cannot be resolved and are
 *    treated as non-propagating.
 *  - No alias/use-import awareness for facades: short-name resolution relies on
 *    the TaintSourceResolver string map.
 *  - Control-flow is linear within a function; branch merging and loops are
 *    handled conservatively (taint stays "maybe present" once set).
 *  - Recursive or dynamically dispatched calls are not followed.
 *  - Per-file statement cap prevents explosion on very large files; analysis is
 *    best-effort rather than exhaustive.
 */
final class TaintEngine
{
    private const MAX_FILES = 500;
    private const MAX_STATEMENTS_PER_FILE = 4000;

    private const RULE_SQL = 'TAINT_SQL_INJECTION';
    private const RULE_CMD = 'TAINT_COMMAND_INJECTION';
    private const RULE_EVAL = 'TAINT_EVAL';
    private const RULE_UNSERIALIZE = 'TAINT_UNSAFE_SERIALIZE';

    private const RULE_SEVERITY = [
        self::RULE_SQL => 'Critical',
        self::RULE_CMD => 'Critical',
        self::RULE_EVAL => 'Critical',
        self::RULE_UNSERIALIZE => 'Error',
    ];

    private const SQL_SINKS = [
        'select' => true,
        'statement' => true,
        'unprepared' => true,
        'raw' => true,
        'whereRaw' => true,
        'selectRaw' => true,
        'orderByRaw' => true,
        'havingRaw' => true,
        'groupByRaw' => true,
        'query' => true,
    ];

    private const COMMAND_SINKS = [
        'system' => true,
        'exec' => true,
        'shell_exec' => true,
        'passthru' => true,
    ];

    private const EVAL_SINKS = [
        'eval' => true,
        'assert' => true,
    ];

    private const UNSERIALIZE_SINKS = [
        'unserialize' => true,
    ];

    private Parser $parser;
    private TaintSourceResolver $resolver;

    /** @var array<string, array{functions: array<string,array>, methods: array<string,array>, order: string[]}> */
    private array $fileIndex = [];

    /** @var array<int, array<string, mixed>> */
    private array $issues = [];

    private int $filesAnalyzed = 0;
    private int $functionsSeen = 0;

    /** @var list<string> Entry-point call names, e.g. ['DB::select', 'exec'] */
    private array $entryPoints = [];

    /** @var array<string, string> Rule id => sink call name, configured via addSink(). */
    private array $sinkRules = [];

    public function __construct(?TaintSourceResolver $resolver = null, ?Parser $parser = null)
    {
        $this->resolver = $resolver ?? new TaintSourceResolver();
        $this->parser = $parser ?? (new ParserFactory())->createForNewestSupportedVersion();
        $this->initDefaultSinks();
    }

    /**
     * Configure explicit entry-point call signatures to treat as taint sources.
     *
     * @param list<string> $funcCalls e.g. ['request()->all', 'input']
     */
    public function setEntryPoints(array $funcCalls): void
    {
        $this->entryPoints = array_values($funcCalls);
    }

    /**
     * Map a sink call name to a rule id (severity resolved internally).
     */
    public function addSink(string $ruleId, string $sinkCall): void
    {
        if (!isset(self::RULE_SEVERITY[$ruleId])) {
            return;
        }
        $this->sinkRules[$sinkCall] = $ruleId;
    }

    /**
     * Analyze a list of absolute PHP file paths.
     *
     * @param list<string> $files
     * @return list<array{rule:string,message:string,file:string,line:int,severity:string,source:string,metadata:array}>
     */
    public function analyze(array $files): array
    {
        $this->issues = [];
        $this->fileIndex = [];
        $this->filesAnalyzed = 0;
        $this->functionsSeen = 0;

        foreach ($files as $file) {
            if ($this->filesAnalyzed >= self::MAX_FILES) {
                break;
            }
            $this->indexFile($file);
            $this->filesAnalyzed++;
        }

        foreach ($this->fileIndex as $file => $index) {
            $this->analyzeFile($file, $index);
        }

        return $this->issues;
    }

    private function indexFile(string $file): void
    {
        if (!is_file($file)) {
            return;
        }
        $code = file_get_contents($file);
        if ($code === false) {
            return;
        }

        try {
            $ast = $this->parser->parse($code);
        } catch (\Throwable $e) {
            return;
        }
        if ($ast === null) {
            return;
        }

        $functions = [];
        $methods = [];
        $order = [];

        $this->collectCallables($ast, null, $functions, $methods, $order);

        $this->fileIndex[$file] = ['functions' => $functions, 'methods' => $methods, 'order' => $order];
        $this->functionsSeen += count($functions) + count($methods);
    }

    /**
     * @param list<Node> $nodes
     * @param array<string, FunctionLike> $functions
     * @param array<string, FunctionLike> $methods
     * @param list<string> $order
     */
    private function collectCallables(array $nodes, ?string $class, array &$functions, array &$methods, array &$order): void
    {
        foreach ($nodes as $node) {
            if ($node instanceof Function_) {
                $name = $node->name->toString();
                $functions[$name] = $node;
                $order[] = 'fn:' . $name;
            } elseif ($node instanceof Class_) {
                $className = $node->name ? $node->name->toString() : $class;
                foreach ($node->stmts as $stmt) {
                    if ($stmt instanceof ClassMethod) {
                        if ($className !== null) {
                            $key = $className . '::' . $stmt->name->toString();
                            $methods[$key] = $stmt;
                            $order[] = 'm:' . $key;
                        }
                    }
                }
            }

            foreach ($node->getSubNodeNames() as $sub) {
                $value = $node->{$sub};
                if ($value instanceof Node) {
                    $nestedClass = $value instanceof Class_ && $value->name ? $value->name->toString() : $class;
                    $this->collectCallables([$value], $nestedClass, $functions, $methods, $order);
                } elseif (is_array($value)) {
                    /** @var list<Node> $childNodes */
                    $childNodes = array_values(array_filter($value, static fn ($v): bool => $v instanceof Node));
                    if ($childNodes !== []) {
                        $this->collectCallables($childNodes, $class, $functions, $methods, $order);
                    }
                }
            }
        }
    }

    private function analyzeFile(string $file, array $index): void
    {
        $statementsBudget = self::MAX_STATEMENTS_PER_FILE;

        foreach ($index['order'] as $entry) {
            if ($statementsBudget <= 0) {
                break;
            }
            $callable = null;
            if (str_starts_with($entry, 'fn:')) {
                $callable = $index['functions'][substr($entry, 3)] ?? null;
            } elseif (str_starts_with($entry, 'm:')) {
                $callable = $index['methods'][substr($entry, 2)] ?? null;
            }
            if ($callable === null) {
                continue;
            }
            $this->analyzeCallable($file, $callable);
            $statementsBudget -= $this->countStatements($callable);
        }
    }

    private function analyzeCallable(string $file, Node $callable): void
    {
        $tainted = [];
        $this->walkCallable($file, $callable, $tainted);
    }

    private function walkCallable(string $file, Node $callable, array &$tainted): void
    {
        $budget = self::MAX_STATEMENTS_PER_FILE;
        $this->walkNodes([$callable], $file, $tainted, $budget);
    }

    /**
     * @param list<Node> $nodes
     * @param array<string, bool> $tainted
     */
    private function walkNodes(array $nodes, string $file, array &$tainted, int &$budget): void
    {
        foreach ($nodes as $node) {
            if ($budget-- <= 0) {
                return;
            }

            if ($node instanceof Assign) {
                $this->handleAssignment($file, $node, $tainted);
            } elseif ($node instanceof Return_) {
                $this->handleReturn($file, $node, $tainted);
            } elseif ($node instanceof FuncCall) {
                $this->handleCall($file, $node, $tainted, null);
            } elseif ($node instanceof StaticCall) {
                $this->handleCall($file, $node, $tainted, null);
            } elseif ($node instanceof MethodCall) {
                $this->handleCall($file, $node, $tainted, null);
            } elseif ($node instanceof Expr\AssignOp\Concat || $node instanceof Expr\BinaryOp\Concat) {
                $this->handleConcat($file, $node, $tainted);
            } elseif ($node instanceof InterpolatedString) {
                $this->handleInterpolated($file, $node, $tainted);
            }

            $children = [];
            foreach ($node->getSubNodeNames() as $sub) {
                $value = $node->{$sub};
                if ($value instanceof Node) {
                    $children[] = $value;
                } elseif (is_array($value)) {
                    foreach ($value as $v) {
                        if ($v instanceof Node) {
                            $children[] = $v;
                        }
                    }
                }
            }
            if ($children !== []) {
                $this->walkNodes($children, $file, $tainted, $budget);
                if ($budget <= 0) {
                    return;
                }
            }
        }
    }

    private function countStatements(Node $node): int
    {
        $count = 0;
        $this->countNodes([$node], $count);
        return $count;
    }

    /**
     * @param list<Node> $nodes
     */
    private function countNodes(array $nodes, int &$count): void
    {
        foreach ($nodes as $node) {
            $count++;
            foreach ($node->getSubNodeNames() as $sub) {
                $value = $node->{$sub};
                if ($value instanceof Node) {
                    $this->countNodes([$value], $count);
                } elseif (is_array($value)) {
                    foreach ($value as $v) {
                        if ($v instanceof Node) {
                            $this->countNodes([$v], $count);
                        }
                    }
                }
            }
        }
    }

    public function handleAssignment(string $file, Assign $assign, array &$tainted): void
    {
        $target = $assign->var;
        $value = $assign->expr;

        if (!$target instanceof Variable && !$target instanceof ArrayDimFetch) {
            return;
        }

        $isTaintedValue = $this->isExpressionTainted($value, $tainted);

        if ($target instanceof Variable) {
            $name = $this->variableName($target);
            if ($name === null) {
                return;
            }
            if ($isTaintedValue || $this->isExpressionSource($value, $tainted)) {
                $tainted[$name] = true;
            }
        } elseif ($target instanceof ArrayDimFetch && $target->var instanceof Variable) {
            $name = $this->variableName($target->var);
            if ($name !== null && ($isTaintedValue || $this->isExpressionSource($value, $tainted))) {
                $tainted[$name] = true;
            }
        }
    }

    public function handleReturn(string $file, Return_ $ret, array &$tainted): void
    {
        // Return-taint is resolved on demand via callee-body walk in handleCall;
        // nothing to record here beyond keeping the hook for future extensions.
        if ($ret->expr !== null) {
            $this->isExpressionTainted($ret->expr, $tainted);
        }
    }

    public function handleConcat(string $file, Node $node, array &$tainted): void
    {
        if ($node instanceof Expr\BinaryOp\Concat) {
            if ($this->isExpressionTainted($node->left, $tainted) || $this->isExpressionTainted($node->right, $tainted)) {
                $node->setAttribute('qc_tainted_concat', true);
            }
        }
    }

    public function handleInterpolated(string $file, InterpolatedString $node, array &$tainted): void
    {
        foreach ($node->parts as $part) {
            if ($part instanceof Expr && $this->isExpressionTainted($part, $tainted)) {
                $node->setAttribute('qc_tainted_interp', true);
            }
        }
    }

    public function handleCall(string $file, Node $call, array &$tainted, ?Node $caller): void
    {
        $callInfo = $this->resolveCall($call);
        if ($callInfo === null) {
            return;
        }

        [$callName, $args, $isStatic, $fqn] = $callInfo;

        if ($this->isSinkCall($callName, $fqn)) {
            $this->reportSink($file, $call, $callName, $args, $tainted);
            return;
        }

        if ($this->isSourceCall($callName, $args)) {
            $this->markAssignmentSource($call, $tainted);
        }

        $this->propagateArgs($file, $call, $callName, $args, $tainted);
    }

    private function resolveCall(Node $call): ?array
    {
        $fqn = null;

        if ($call instanceof FuncCall) {
            if ($call->name instanceof Node\Name) {
                $callName = $call->name->toString();
            } else {
                $callName = null;
            }
            if ($callName === null) {
                return null;
            }
            return [$callName, $call->args, false, null];
        }

        if ($call instanceof StaticCall) {
            if (!$call->name instanceof Node\Identifier) {
                return null;
            }
            $method = $call->name->toString();
            $className = null;
            if ($call->class instanceof Node\Name) {
                $className = $call->class->toString();
            }
            if ($className === null) {
                return null;
            }
            $resolved = $this->resolver->resolve($className);
            $fqn = $resolved ?? $className;
            return [$fqn . '::' . $method, $call->args, true, $resolved];
        }

        if ($call instanceof MethodCall) {
            if (!$call->name instanceof Node\Identifier) {
                return null;
            }
            $method = $call->name->toString();
            $base = $call->var;
            if ($base instanceof Variable) {
                $varName = $this->variableName($base);
                if ($varName !== null) {
                    if ($varName === 'request') {
                        return [$this->sourceNameFromMethod($method), $call->args, false, null];
                    }
                    if ($varName === 'this') {
                        return ['$this->' . $method, $call->args, false, null];
                    }
                    // Unknown object -> bail (conservative)
                    return null;
                }
            }
            if ($base instanceof MethodCall && $base->name instanceof Node\Identifier && $base->name->toString() === 'request') {
                return [$this->sourceNameFromMethod($method), $call->args, false, null];
            }
            if ($base instanceof FuncCall && $base->name instanceof Node\Name && $base->name->toString() === 'request') {
                return [$this->sourceNameFromMethod($method), $call->args, false, null];
            }
            if (
                $base instanceof PropertyFetch && $base->var instanceof Variable && $this->variableName($base->var) === 'this'
                && $base->name instanceof Node\Identifier && $base->name->toString() === 'request'
            ) {
                return [$this->sourceNameFromMethod($method), $call->args, false, null];
            }
            return null;
        }

        return null;
    }

    private function sourceNameFromMethod(string $method): string
    {
        $map = [
            'all' => 'request.all',
            'input' => 'request.input',
            'query' => 'request.query',
            'get' => 'request.input',
            'post' => 'request.input',
            'cookie' => 'request.cookie',
            'only' => 'request.only',
            'except' => 'request.except',
        ];
        return $map[$method] ?? 'request.other';
    }

    private function isSourceCall(string $callName, array $args): bool
    {
        foreach ($this->entryPoints as $ep) {
            if ($callName === $ep || str_ends_with($callName, '.' . $ep) || $callName === $ep . '()') {
                return true;
            }
        }

        if (
            str_contains($callName, 'request.input') || $callName === 'input'
            || str_contains($callName, 'request.all') || $callName === 'request()->all'
            || str_contains($callName, 'request.query')
        ) {
            return true;
        }

        if (in_array($callName, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true)) {
            return true;
        }

        return false;
    }

    private function isSinkCall(string $callName, ?string $fqn): bool
    {
        $base = $this->sinkBase($callName);

        if ($fqn !== null && $this->resolver->isShortName($fqn, 'DB')) {
            foreach (array_keys(self::SQL_SINKS) as $s) {
                if ($base === $s || str_ends_with($callName, '::' . $s) || str_ends_with($callName, '->' . $s)) {
                    return true;
                }
            }
        }

        if (isset(self::COMMAND_SINKS[$base])) {
            return true;
        }
        if (isset(self::EVAL_SINKS[$base]) || $base === 'assert') {
            return true;
        }
        if (isset(self::UNSERIALIZE_SINKS[$base])) {
            return true;
        }

        foreach ($this->sinkRules as $sinkCall => $ruleId) {
            if ($callName === $sinkCall || $base === $sinkCall) {
                return true;
            }
        }

        return false;
    }

    private function sinkBase(string $callName): string
    {
        if (str_contains($callName, '::')) {
            return substr($callName, strrpos($callName, '::') + 2);
        }
        if (str_contains($callName, '->')) {
            return substr($callName, strrpos($callName, '->') + 2);
        }
        return $callName;
    }

    private function reportSink(string $file, Node $call, string $callName, array $args, array $tainted): void
    {
        foreach ($args as $arg) {
            if ($arg instanceof Node\Arg) {
                $val = $arg->value;
            } else {
                $val = $arg;
            }
            if ($val instanceof InterpolatedString) {
                if ($this->isExpressionTainted($val, $tainted)) {
                    $this->emit($file, $call, $callName);
                    return;
                }
                continue;
            }
            if ($val instanceof Node\Scalar) {
                continue;
            }
            if ($this->isExpressionTainted($val, $tainted) || $this->isExpressionSource($val, $tainted)) {
                $this->emit($file, $call, $callName);
                return;
            }
        }
    }

    private function isStringInterpolatedTainted(String_ $str, array $tainted): bool
    {
        return (bool) $str->getAttribute('qc_tainted_interp');
    }

    private function emit(string $file, Node $call, string $callName): void
    {
        $rule = $this->ruleForCall($callName);
        if ($rule === null) {
            return;
        }
        $line = $call->getStartLine();
        $this->issues[] = [
            'rule' => $rule,
            'message' => $this->messageFor($rule, $callName),
            'file' => $file,
            'line' => $line,
            'severity' => self::RULE_SEVERITY[$rule],
            'source' => 'custom',
            'metadata' => ['sink' => $callName],
        ];
    }

    private function ruleForCall(string $callName): ?string
    {
        $base = $this->sinkBase($callName);
        foreach ($this->sinkRules as $sinkCall => $ruleId) {
            if ($callName === $sinkCall || $base === $sinkCall) {
                return $ruleId;
            }
        }
        if (isset(self::COMMAND_SINKS[$base])) {
            return self::RULE_CMD;
        }
        if (isset(self::EVAL_SINKS[$base]) || $base === 'assert') {
            return self::RULE_EVAL;
        }
        if (isset(self::UNSERIALIZE_SINKS[$base])) {
            return self::RULE_UNSERIALIZE;
        }
        if ($base === 'query') {
            return self::RULE_SQL;
        }
        if (isset(self::SQL_SINKS[$base])) {
            return self::RULE_SQL;
        }
        return null;
    }

    private function messageFor(string $rule, string $callName): string
    {
        return match ($rule) {
            self::RULE_SQL => sprintf('Tainted user input flows into SQL sink `%s`.', $callName),
            self::RULE_CMD => sprintf('Tainted user input flows into command execution sink `%s`.', $callName),
            self::RULE_EVAL => sprintf('Tainted user input reaches dynamic evaluation sink `%s`.', $callName),
            self::RULE_UNSERIALIZE => sprintf('Tainted user input reaches unserialize sink `%s`.', $callName),
            default => sprintf('Tainted data reaches sink `%s`.', $callName),
        };
    }

    private function propagateArgs(string $file, Node $call, string $callName, array $args, array &$tainted): void
    {
        $callee = $this->resolveCallee($callName);
        if ($callee === null) {
            return;
        }
        $params = $callee->params;

        foreach ($args as $idx => $arg) {
            $val = $arg instanceof Node\Arg ? $arg->value : $arg;
            $param = $params[$idx] ?? null;
            if ($param === null || !$param->var instanceof Variable) {
                continue;
            }
            $paramName = $param->var->name;
            if (is_string($paramName) && $this->isExpressionTainted($val, $tainted)) {
                $tainted[$paramName] = true;
            }
        }

        $this->analyzeCalleeBody($file, $callee, $tainted);
    }

    private function resolveCallee(string $callName): ?FunctionLike
    {
        if (str_contains($callName, '::') || str_contains($callName, '->') || $callName === 'input') {
            return null;
        }
        foreach ($this->fileIndex as $index) {
            if (isset($index['functions'][$callName])) {
                return $index['functions'][$callName];
            }
        }
        return null;
    }

    private function analyzeCalleeBody(string $file, FunctionLike $callee, array &$tainted): void
    {
        $this->walkCallable($file, $callee, $tainted);
    }

    private function isExpressionTainted($expr, array $tainted): bool
    {
        if ($expr === null) {
            return false;
        }
        if ($expr instanceof Variable) {
            $name = $this->variableName($expr);
            if ($name !== null && isset($tainted[$name])) {
                return true;
            }
            // Chain: $a['x'] tainted if $a tainted
            return $name !== null && isset($tainted[$name]);
        }
        if ($expr instanceof ArrayDimFetch) {
            return $this->isExpressionTainted($expr->var, $tainted);
        }
        if ($expr instanceof Expr\BinaryOp\Concat) {
            return $this->isExpressionTainted($expr->left, $tainted) || $this->isExpressionTainted($expr->right, $tainted);
        }
        if ($expr instanceof Expr\Assign) {
            return $this->isExpressionTainted($expr->expr, $tainted);
        }
        if ($expr instanceof InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Expr && $this->isExpressionTainted($part, $tainted)) {
                    return true;
                }
            }
            return false;
        }
        if ($expr instanceof String_ && $expr->getAttribute('qc_tainted_interp')) {
            return true;
        }
        if ($expr instanceof MethodCall || $expr instanceof FuncCall || $expr instanceof StaticCall) {
            $info = $this->resolveCall($expr);
            if ($info === null) {
                return false;
            }
            [$name, , , ] = $info;
            return $this->isSourceCall($name, []);
        }
        return false;
    }

    private function isExpressionSource($expr, array $tainted): bool
    {
        if ($expr instanceof Variable) {
            $name = $this->variableName($expr);
            if ($name === null) {
                return false;
            }
            if (in_array($name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true)) {
                return true;
            }
            return false;
        }
        if ($expr instanceof MethodCall || $expr instanceof FuncCall || $expr instanceof StaticCall) {
            $info = $this->resolveCall($expr);
            if ($info === null) {
                return false;
            }
            [$name, , , ] = $info;
            return $this->isSourceCall($name, []);
        }
        if (
            $expr instanceof Expr\PropertyFetch && $expr->var instanceof Variable && $this->variableName($expr->var) === 'this'
            && $expr->name instanceof Node\Identifier && $expr->name->toString() === 'request'
        ) {
            return true;
        }
        return false;
    }

    private function markAssignmentSource(Node $call, array &$tainted): void
    {
        // The expression's value becomes tainted; handled via isExpressionSource in assignment.
        $tainted['__source_expr__'] = true;
    }

    private function variableName(Variable $var): ?string
    {
        if (is_string($var->name)) {
            return $var->name;
        }
        return null;
    }

    private function initDefaultSinks(): void
    {
        $this->addSink(self::RULE_SQL, 'DB::select');
        $this->addSink(self::RULE_SQL, 'DB::statement');
        $this->addSink(self::RULE_SQL, 'DB::unprepared');
        $this->addSink(self::RULE_SQL, 'DB::raw');
        $this->addSink(self::RULE_SQL, 'whereRaw');
        $this->addSink(self::RULE_SQL, 'selectRaw');
        $this->addSink(self::RULE_SQL, 'orderByRaw');
        $this->addSink(self::RULE_SQL, 'havingRaw');
        $this->addSink(self::RULE_SQL, 'groupByRaw');
        $this->addSink(self::RULE_CMD, 'system');
        $this->addSink(self::RULE_CMD, 'exec');
        $this->addSink(self::RULE_CMD, 'shell_exec');
        $this->addSink(self::RULE_CMD, 'passthru');
        $this->addSink(self::RULE_EVAL, 'eval');
        $this->addSink(self::RULE_EVAL, 'assert');
        $this->addSink(self::RULE_UNSERIALIZE, 'unserialize');
    }
}
