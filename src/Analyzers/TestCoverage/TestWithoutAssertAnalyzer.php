<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class TestWithoutAssertAnalyzer
{
    private const RULE = 'TEST_WITHOUT_ASSERT';

    private const ASSERT_RE = '/(assert|expects|expectException|->assert|assertTrue|assertFalse|assertEquals|assertSame|assertNotNull)/i';

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if (!$this->isTestFile($file)) {
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

        foreach ($finder->findInstanceOf($ast, Node\Stmt\ClassMethod::class) as $method) {
            if (!$this->isTestMethod($method)) {
                continue;
            }

            $body = $method->stmts;
            if ($body === null) {
                continue;
            }

            if ($this->hasAssertion($body)) {
                continue;
            }

            $methodName = $method->name instanceof Node\Identifier ? $method->name->toString() : '(anonymous)';
            $issues[] = new Issue(
                self::RULE,
                sprintf('Test method %s() contains no assertion statements.', $methodName),
                $file,
                $method->getStartLine(),
                Severity::Warning,
                'custom',
                ['method' => $methodName],
                Confidence::Low
            );
        }

        return $issues;
    }

    private function isTestMethod(Node\Stmt\ClassMethod $method): bool
    {
        if (!$method->isPublic()) {
            return false;
        }

        $name = $method->name instanceof Node\Identifier ? $method->name->toString() : '';

        if (str_starts_with($name, 'test')) {
            return true;
        }

        foreach ($method->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if ($attr->name instanceof Node\Name && $attr->name->toString() === 'test') {
                    return true;
                }
            }
        }

        return false;
    }

    private function hasAssertion(array $body): bool
    {
        $finder = new NodeFinder();
        $source = '';

        $methodCalls = $finder->findInstanceOf($body, Node\Expr\MethodCall::class);
        foreach ($methodCalls as $call) {
            if ($call->name instanceof Node\Identifier) {
                $name = $call->name->toString();
                if (
                    str_starts_with($name, 'assert')
                    || str_starts_with($name, 'expect')
                    || str_starts_with($name, 'expectException')
                ) {
                    return true;
                }
            }
        }

        $funcCalls = $finder->findInstanceOf($body, Node\Expr\FuncCall::class);
        foreach ($funcCalls as $call) {
            if ($call->name instanceof Node\Name) {
                $name = $call->name->toString();
                if (str_starts_with($name, 'assert') || str_starts_with($name, 'expect')) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isTestFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_contains($normalized, '/tests/') || str_starts_with($normalized, 'tests/');
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
