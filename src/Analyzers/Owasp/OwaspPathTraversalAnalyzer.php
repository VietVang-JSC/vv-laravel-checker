<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A01 Path Traversal (file / Storage / download sinks).
 *
 * Sinks: file_get_contents/file_put_contents/fopen/file/readfile,
 * Storage::get/put/delete/download, File::get/put/delete (facade +
 * Filesystem), response()->download/file, and dynamic include/require.
 *
 * Assumes: file sinks are flagged when their path argument is a variable, a property/method call, or
 * a concat/interpolation that resolves to request input. A `storage_path()`/`base_path()` wrapper only
 * sanitizes when every argument is itself safe (literal or `basename()`-wrapped); otherwise the taint
 * flows through. This is a heuristic, not a full data-flow analysis.
 *
 * Deliberately not flagged: string literals (including `storage_path()`/`base_path()` with literal-only
 * args), expressions wrapped in `basename()` (traversal stripped), deploy-time `env()`/`config()`
 * lookups, variables/properties named like local paths ($file, $path, $source, ...),
 * and sinks inside test paths.
 */
final class OwaspPathTraversalAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_PATH_TRAVERSAL';

    private const FUNC_SINKS = ['file_get_contents', 'file_put_contents', 'fopen', 'file', 'readfile'];

    private const STORAGE_METHODS = ['get', 'put', 'delete', 'download'];

    private const FILE_METHODS = ['get', 'put', 'delete'];

    private const RESPONSE_METHODS = ['download', 'file'];

    private const PATH_HELPERS = [
        'storage_path', 'base_path', 'public_path', 'resource_path',
        'database_path', 'app_path', 'config_path', 'lang_path', 'dirname',
    ];

    private const CONFIG_FUNCS = ['env', 'config'];

    /**
     * @param list<string> $files
     * @return Issue[]
     */
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
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $roots = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $roots[] = $node;
            }
        }
        $origins = $this->variableOrigins($roots);

        $issues = [];
        $nodes = $this->finder()->find($roots, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\Include_;
        });

        foreach ($nodes as $node) {
            if ($node instanceof Node\Expr\Include_) {
                $sink = $this->includeSinkLabel($node);
                if ($sink === null) {
                    continue;
                }
                // include/require with a dynamic path is potential LFI (code
                // execution) — the local-name heuristic never applies here,
                // but a variable provably assigned a safe path does not flag.
                if (!$this->isTaintedPath($node->expr, false, $origins)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential path traversal: user input flows into %s.', $sink),
                    $file,
                    $node->getStartLine(),
                    Severity::Error,
                    ['sink' => $sink]
                );
                continue;
            }

            if ($node instanceof Node\Expr\FuncCall) {
                if (!$node->name instanceof Node\Name) {
                    continue;
                }
                $fn = strtolower($node->name->toString());
                if (!in_array($fn, self::FUNC_SINKS, true)) {
                    continue;
                }
                $arg = $node->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isTaintedPath($arg->value, true, $origins)) {
                    continue;
                }
                $sink = $fn . '()';
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential path traversal: user input flows into %s.', $sink),
                    $file,
                    $node->getStartLine(),
                    Severity::Error,
                    ['sink' => $sink]
                );
                continue;
            }

            if ($node instanceof Node\Expr\StaticCall) {
                if (!$node->class instanceof Node\Name || !$node->name instanceof Node\Identifier) {
                    continue;
                }
                $method = strtolower($node->name->toString());
                $class = $node->class->toString();
                $label = null;
                if (in_array($method, self::STORAGE_METHODS, true) && $this->isStorageClass($class)) {
                    $label = 'Storage::' . $node->name->toString() . '()';
                } elseif (in_array($method, self::FILE_METHODS, true) && $this->isFileClass($class)) {
                    $label = 'File::' . $node->name->toString() . '()';
                }
                if ($label === null) {
                    continue;
                }
                $arg = $node->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isTaintedPath($arg->value, true, $origins)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential path traversal: user input flows into %s.', $label),
                    $file,
                    $node->getStartLine(),
                    Severity::Error,
                    ['sink' => $label]
                );
                continue;
            }

            if ($node instanceof Node\Expr\MethodCall) {
                if (!$node->name instanceof Node\Identifier) {
                    continue;
                }
                $method = strtolower($node->name->toString());
                if (!in_array($method, self::RESPONSE_METHODS, true)) {
                    continue;
                }
                if (!$this->isResponseReceiver($node->var)) {
                    continue;
                }
                $arg = $node->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isTaintedPath($arg->value, true, $origins)) {
                    continue;
                }
                $sink = 'response()->' . $node->name->toString() . '()';
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Potential path traversal: user input flows into %s.', $sink),
                    $file,
                    $node->getStartLine(),
                    Severity::Error,
                    ['sink' => $sink]
                );
            }
        }

        return $issues;
    }

    private function includeSinkLabel(Node\Expr\Include_ $node): ?string
    {
        return match ($node->type) {
            Node\Expr\Include_::TYPE_INCLUDE => 'include',
            Node\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Node\Expr\Include_::TYPE_REQUIRE => 'require',
            Node\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
            default => null,
        };
    }

    private function isStorageClass(string $class): bool
    {
        $normalized = strtolower(ltrim($class, '\\'));

        return $normalized === 'storage' || str_ends_with($normalized, '\\storage');
    }

    private function isFileClass(string $class): bool
    {
        $normalized = strtolower(ltrim($class, '\\'));

        return $normalized === 'file'
            || $normalized === 'filesystem'
            || str_ends_with($normalized, '\\file')
            || str_ends_with($normalized, '\\filesystem');
    }

    private function isResponseReceiver(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            return strtolower($expr->name->toString()) === 'response';
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->isResponseReceiver($expr->var);
        }

        return false;
    }

    /**
     * @param array<string, list<Node\Expr>> $origins
     */
    private function isTaintedPath(Node\Expr $expr, bool $allowNameHeuristic = true, array $origins = []): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return false;
        }

        if ($expr instanceof Node\Scalar\LNumber || $expr instanceof Node\Scalar\DNumber) {
            return false;
        }

        if ($expr instanceof Node\Expr\ConstFetch || $expr instanceof Node\Scalar\MagicConst) {
            return false;
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            return false;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            if ($this->isSafeVariableOrigin($expr->name, $origins, [])) {
                return false;
            }
            if ($allowNameHeuristic && $this->rootVariableName($expr) !== 'request') {
                return !$this->isLocalPathName($expr->name);
            }

            return true;
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            if ($allowNameHeuristic && $this->rootVariableName($expr) !== 'request') {
                return !$this->isLocalPathName($expr->name->toString());
            }

            return true;
        }

        if (
            $expr instanceof Node\Expr\MethodCall
            && $expr->name instanceof Node\Identifier
            && $this->rootVariableName($expr) !== 'request'
            && $this->isLocalPathName($expr->name->toString())
        ) {
            return false;
        }

        if (
            $expr instanceof Node\Expr\StaticCall
            && $expr->name instanceof Node\Identifier
            && $expr->class instanceof Node\Name
        ) {
            $class = strtolower(ltrim($expr->class->toString(), '\\'));
            if ($class === 'request' || str_ends_with($class, '\\request')) {
                return true;
            }
            if ($allowNameHeuristic && $this->isLocalPathName($expr->name->toString())) {
                return false;
            }
        }

        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
            $fn = strtolower($expr->name->toString());
            if ($fn === 'basename') {
                return false;
            }
            if (in_array($fn, self::CONFIG_FUNCS, true)) {
                return false;
            }
            if (in_array($fn, self::PATH_HELPERS, true)) {
                if ($expr->args === []) {
                    return false;
                }
                foreach ($expr->args as $arg) {
                    if (
                        $arg instanceof Node\Arg
                        && $this->isTaintedPath($arg->value, $allowNameHeuristic, $origins)
                    ) {
                        return true;
                    }
                }

                return false;
            }

            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isTaintedPath($expr->left, $allowNameHeuristic, $origins)
                || $this->isTaintedPath($expr->right, $allowNameHeuristic, $origins);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if (
                    $part instanceof Node\Expr
                    && $this->isTaintedPath($part, $allowNameHeuristic, $origins)
                ) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp) {
            return $this->isTaintedPath($expr->left, $allowNameHeuristic, $origins)
                || $this->isTaintedPath($expr->right, $allowNameHeuristic, $origins);
        }

        if ($expr instanceof Node\Expr\Ternary) {
            if (
                $expr->if !== null
                && $this->isTaintedPath($expr->if, $allowNameHeuristic, $origins)
            ) {
                return true;
            }

            return $this->isTaintedPath($expr->else, $allowNameHeuristic, $origins);
        }

        if (
            $expr instanceof Node\Expr\Variable
            || $expr instanceof Node\Expr\PropertyFetch
            || $expr instanceof Node\Expr\NullsafePropertyFetch
            || $expr instanceof Node\Expr\MethodCall
            || $expr instanceof Node\Expr\NullsafeMethodCall
            || $expr instanceof Node\Expr\ArrayDimFetch
            || $expr instanceof Node\Expr\StaticCall
            || $expr instanceof Node\Expr\New_
        ) {
            return true;
        }

        return $this->isTaintedExpr($expr);
    }

    /**
     * A variable assigned only safe path origins (literals, magic constants,
     * basename(), path helpers with safe args, deploy-time config) is safe
     * even for include/require. Any other assignment keeps it flagged.
     *
     * @param array<string, list<Node\Expr>> $origins
     * @param array<string, true> $seen cycle guard
     */
    private function isSafeVariableOrigin(string $name, array $origins, array $seen): bool
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
            if (!$this->isSafeIncludeRhs($rhs, $origins, $seen)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string, list<Node\Expr>> $origins
     * @param array<string, true> $seen
     */
    private function isSafeIncludeRhs(Node\Expr $expr, array $origins, array $seen): bool
    {
        if (
            $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Scalar\LNumber
            || $expr instanceof Node\Scalar\DNumber
            || $expr instanceof Node\Expr\ConstFetch
            || $expr instanceof Node\Scalar\MagicConst
            || $expr instanceof Node\Expr\ClassConstFetch
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $this->isSafeVariableOrigin($expr->name, $origins, $seen);
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && in_array(
                strtolower($expr->name->toString()),
                array_merge(['basename'], self::PATH_HELPERS, self::CONFIG_FUNCS),
                true
            )
        ) {
            foreach ($expr->args as $arg) {
                if ($arg instanceof Node\Arg && !$this->isSafeIncludeRhs($arg->value, $origins, $seen)) {
                    return false;
                }
            }

            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isSafeIncludeRhs($expr->left, $origins, $seen)
                && $this->isSafeIncludeRhs($expr->right, $origins, $seen);
        }

        return false;
    }
}
