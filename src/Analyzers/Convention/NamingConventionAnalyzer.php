<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Convention;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class NamingConventionAnalyzer
{
    private const RULE = 'NAMING_CONVENTION';

    private const BOOL_PREFIXES = ['is', 'has', 'can', 'should'];

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

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new NodeFinder();
        $normalized = str_replace('\\', '/', $file);

        foreach ($finder->findInstanceOf($ast, Node\Stmt\Class_::class) as $class) {
            $className = $class->name ? $class->name->toString() : null;
            if ($className === null) {
                continue;
            }

            if (str_contains($normalized, '/Controllers/') && !str_ends_with($className, 'Controller')) {
                $issues[] = $this->issue($file, $class, sprintf('Controller class "%s" must end with "Controller".', $className));
            }
            if (str_contains($normalized, '/Services/') && !str_ends_with($className, 'Service')) {
                $issues[] = $this->issue($file, $class, sprintf('Service class "%s" must end with "Service".', $className));
            }
            if (str_contains($normalized, '/Repositories/') && !str_ends_with($className, 'Repository')) {
                $issues[] = $this->issue($file, $class, sprintf('Repository class "%s" must end with "Repository".', $className));
            }

            if ($this->psr4Mismatch($file, $className, $normalized)) {
                $issues[] = $this->issue($file, $class, sprintf('Class "%s" does not match its PSR-4 file location.', $className));
            }

            foreach ($class->getMethods() as $method) {
                if ($method->isMagic()) {
                    continue;
                }
                $methodName = $method->name instanceof Node\Identifier ? $method->name->toString() : '';
                $methodName = lcfirst($methodName);

                foreach (self::BOOL_PREFIXES as $prefix) {
                    if (str_starts_with($methodName, $prefix) && !$this->declaredReturnBool($method)) {
                        $issues[] = $this->issue(
                            $file,
                            $method,
                            sprintf('Method "%s()" starts with "%s" and should declare a bool return type.', $methodName, $prefix)
                        );
                        break;
                    }
                }
            }
        }

        return $issues;
    }

    private function declaredReturnBool(Node\Stmt\ClassMethod $method): bool
    {
        $type = $method->returnType;
        if ($type instanceof Node\Identifier && strtolower($type->toString()) === 'bool') {
            return true;
        }
        if ($type instanceof Node\NullableType && $type->type instanceof Node\Identifier && strtolower($type->type->toString()) === 'bool') {
            return true;
        }

        return false;
    }

    private function psr4Mismatch(string $file, string $className, string $normalized): bool
    {
        $expected = str_replace('\\', '/', $className) . '.php';
        $relative = $this->relativePath($normalized);

        if ($relative === null) {
            return false;
        }

        $lastSegment = strtolower($relative);
        $expectedLast = strtolower(substr($expected, strrpos($expected, '/') + 1));

        return $lastSegment === $expectedLast;
    }

    private function relativePath(string $normalized): ?string
    {
        $root = $this->appRoot();
        if ($root === null) {
            return null;
        }

        $rootNormalized = str_replace('\\', '/', rtrim($root, '/')) . '/';
        if (!str_starts_with($normalized, $rootNormalized)) {
            return null;
        }

        return substr($normalized, strlen($rootNormalized));
    }

    private function issue(string $file, Node $node, string $message): Issue
    {
        return new Issue(
            self::RULE,
            $message,
            $file,
            $node->getStartLine(),
            Severity::Info,
            'custom',
            [],
            Confidence::Low
        );
    }

    private function appRoot(): ?string
    {
        foreach ([getcwd(), dirname(__DIR__, 4)] as $candidate) {
            if (is_string($candidate) && is_dir($candidate . '/app')) {
                return $candidate;
            }
        }

        return null;
    }

    private function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }

    private function parse(string $code): ?array
    {
        try {
            $parser = (new ParserFactory())->createForNewestSupportedVersion();

            return $parser->parse($code);
        } catch (\Throwable $e) {
            return null;
        }
    }
}
