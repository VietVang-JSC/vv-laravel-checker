<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class TestWithoutAssertAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'TEST_WITHOUT_ASSERT';

    /**
     * @param list<string> $files absolute paths
     * @return list<Issue>
     */
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

    /**
     * @return list<Issue>
     */
    private function analyzeFile(string $file): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();

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

        $name = $method->name->toString();

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

    /**
     * @param array<Node\Stmt> $body
     */
    private function hasAssertion(array $body): bool
    {
        $finder = new CountingNodeFinder();
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
}
