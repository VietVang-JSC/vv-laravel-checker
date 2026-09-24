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
