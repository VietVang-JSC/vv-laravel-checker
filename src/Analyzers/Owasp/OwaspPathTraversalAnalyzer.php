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
 * Assumes: file sinks are flagged when their path argument is a variable, a property/method call, or
 * a concat/interpolation that resolves to request input. A `storage_path()`/`base_path()` wrapper only
 * sanitizes when every argument is itself safe (literal or `basename()`-wrapped); otherwise the taint
 * flows through. This is a heuristic, not a full data-flow analysis.
 *
 * Deliberately not flagged: string literals (including `storage_path()`/`base_path()` with literal-only
 * args), expressions wrapped in `basename()` (traversal stripped), deploy-time `env()`/`config()`
 * lookups, and sinks inside test paths.
 */
final class OwaspPathTraversalAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_PATH_TRAVERSAL';

    private const FUNC_SINKS = ['file_get_contents', 'file_put_contents', 'fopen', 'file', 'readfile'];

    private const STORAGE_METHODS = ['get', 'put', 'delete', 'download'];

    private const RESPONSE_METHODS = ['download', 'file'];

    private const PATH_HELPERS = ['storage_path', 'base_path'];

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

        $issues = [];
        $nodes = $this->finder()->find($ast, function (Node $node): bool {
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
                if (!$this->isTaintedPath($node->expr)) {
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
                if (!$this->isTaintedPath($arg->value)) {
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
                if (!in_array($method, self::STORAGE_METHODS, true)) {
                    continue;
                }
                if (!$this->isStorageClass($node->class->toString())) {
                    continue;
                }
                $arg = $node->args[0] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if (!$this->isTaintedPath($arg->value)) {
                    continue;
                }
                $sink = 'Storage::' . $node->name->toString() . '()';
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
                if (!$this->isTaintedPath($arg->value)) {
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

    private function isTaintedPath(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return false;
        }

        if ($expr instanceof Node\Scalar\LNumber || $expr instanceof Node\Scalar\DNumber) {
            return false;
        }

        if ($expr instanceof Node\Expr\ConstFetch) {
            return false;
        }

        if ($expr instanceof Node\Expr\ClassConstFetch) {
            return false;
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
                    if ($arg instanceof Node\Arg && $this->isTaintedPath($arg->value)) {
                        return true;
                    }
                }

                return false;
            }

            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isTaintedPath($expr->left) || $this->isTaintedPath($expr->right);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->isTaintedPath($part)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Node\Expr\BinaryOp) {
            return $this->isTaintedPath($expr->left) || $this->isTaintedPath($expr->right);
        }

        if ($expr instanceof Node\Expr\Ternary) {
            if ($expr->if !== null && $this->isTaintedPath($expr->if)) {
                return true;
            }

            return $this->isTaintedPath($expr->else);
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
}
