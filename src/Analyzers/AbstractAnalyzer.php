<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

abstract class AbstractAnalyzer
{
    /**
     * @param list<string> $files absolute paths
     * @return Issue[]
     */
    abstract public function analyze(array $files): array;

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    protected function isTestPath(string $path): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $path));

        return str_contains($normalized, '/tests/')
            || str_contains($normalized, '/test/')
            || str_ends_with($normalized, 'test.php');
    }

    protected function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }

    protected function parse(string $code): ?array
    {
        try {
            $parser = (new ParserFactory())->createForNewestSupportedVersion();

            return $parser->parse($code);
        } catch (\Throwable $e) {
            return null;
        }
    }

    protected function finder(): NodeFinder
    {
        return new NodeFinder();
    }

    protected function makeIssue(
        string $rule,
        string $message,
        string $file,
        ?int $line,
        Severity $severity,
        array $metadata = [],
        Confidence $confidence = Confidence::High,
    ): Issue {
        return new Issue($rule, $message, $file, $line, $severity, 'custom', $metadata, $confidence);
    }

    protected function exprName(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Expr\Variable) {
            return is_string($expr->name) ? $expr->name : null;
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            $base = $this->exprName($expr->var) ?? '?';

            return $base . '->' . $expr->name->toString();
        }

        return null;
    }

    protected function isTaintedExpr(Node\Expr $expr): bool
    {
        if (
            $expr instanceof Node\Expr\Variable
            || $expr instanceof Node\Expr\PropertyFetch
            || $expr instanceof Node\Expr\MethodCall
            || $expr instanceof Node\Expr\FuncCall
            || $expr instanceof Node\Expr\ArrayDimFetch
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\BinaryOp) {
            return $this->isTaintedExpr($expr->left) || $this->isTaintedExpr($expr->right);
        }

        return false;
    }

    /**
     * Name hints for local filesystem paths. A variable/property whose name
     * contains a local hint (and no remote hint) refers to a local path, not
     * a URL — e.g. $file, $source, $fullPath, $outputDir. Shared by SSRF and
     * traversal analyzers so both stay silent on the same naming convention.
     * Note: 'dir' also matches words like 'dirty' — accepted trade-off, the
     * heuristic only silences (never confirms) and reviewers see the rest.
     */
    private const LOCAL_NAME_HINTS = [
        'path', 'file', 'filepath', 'filename', 'fullpath', 'source', 'target', 'local', 'dir',
    ];

    private const REMOTE_NAME_HINTS = [
        'url', 'uri', 'endpoint', 'host', 'domain', 'link', 'href', 'remote', 'webhook', 'feed',
    ];

    protected function isLocalPathName(string $name): bool
    {
        $lower = strtolower($name);
        foreach (self::REMOTE_NAME_HINTS as $hint) {
            if (str_contains($lower, $hint)) {
                return false;
            }
        }

        foreach (self::LOCAL_NAME_HINTS as $hint) {
            if (str_contains($lower, $hint)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Root variable name of a fetch chain ($request in $request->file, $a in
     * $a->b()->c), or 'request' for the request() helper. Used to exempt
     * request-derived expressions from local-path-name heuristics.
     */
    protected function rootVariableName(Node\Expr $expr): ?string
    {
        $current = $expr;
        while (
            $current instanceof Node\Expr\PropertyFetch
            || $current instanceof Node\Expr\MethodCall
            || $current instanceof Node\Expr\ArrayDimFetch
            || $current instanceof Node\Expr\NullsafePropertyFetch
            || $current instanceof Node\Expr\NullsafeMethodCall
        ) {
            $current = $current->var;
        }

        if ($current instanceof Node\Expr\Variable && is_string($current->name)) {
            return strtolower($current->name);
        }

        if (
            $current instanceof Node\Expr\FuncCall
            && $current->name instanceof Node\Name
            && strtolower($current->name->toString()) === 'request'
        ) {
            return 'request';
        }

        return null;
    }

    /**
     * File-level map of variable name to every assigned right-hand side.
     *
     * @param list<Node> $nodes
     * @return array<string, list<Node\Expr>>
     */
    protected function variableOrigins(array $nodes): array
    {
        $origins = [];
        $assigns = $this->finder()->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Assign;
        });
        foreach ($assigns as $assign) {
            if (
                $assign instanceof Node\Expr\Assign
                && $assign->var instanceof Node\Expr\Variable
                && is_string($assign->var->name)
            ) {
                $origins[$assign->var->name][] = $assign->expr;
            }
        }

        return $origins;
    }

    /**
     * @return list<string>
     */
    protected function listPhpFiles(string $dir): array
    {
        $files = [];
        if (!is_dir($dir)) {
            return $files;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }
}
