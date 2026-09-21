<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\TestCoverage;

use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class MissingTestAnalyzer extends AbstractAnalyzer
{
    /**
     * @param list<string> $scopes e.g. ['services', 'repositories'] or ['models']
     */
    public function __construct(private array $scopes = ['services', 'models'])
    {
    }

    public function analyze(array $files): array
    {
        $testNames = $this->collectTestNames($files);
        $issues = [];

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }

            $scope = $this->scopeOf($file);
            if ($scope === null) {
                continue;
            }

            $classBase = $this->classBaseName($file);
            if ($classBase === null) {
                continue;
            }

            $rule = $this->ruleFor($scope);
            $testClassBase = $classBase . 'Test';

            if (isset($testNames[$testClassBase])) {
                continue;
            }

            if ($scope === 'models' && !$this->modelHasCustomLogic($file)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                $rule,
                sprintf(
                    'No test file found for %s (%s). Expected a test named %s.php.',
                    $classBase,
                    $scope,
                    $testClassBase
                ),
                $file,
                1,
                Severity::Warning,
                ['class' => $classBase, 'scope' => $scope, 'expected_test' => $testClassBase],
                Confidence::Low
            );
        }

        return $issues;
    }

    private function scopeOf(string $file): ?string
    {
        $normalized = str_replace('\\', '/', $file);

        foreach ($this->scopes as $scope) {
            $needle = '/app/' . ucfirst($scope) . '/';
            if (str_contains($normalized, $needle)) {
                return strtolower($scope);
            }
        }

        return null;
    }

    private function ruleFor(string $scope): string
    {
        return match ($scope) {
            'models' => 'MISSING_MODEL_TEST',
            'repositories' => 'MISSING_SERVICE_TEST',
            default => 'MISSING_SERVICE_TEST',
        };
    }

    private function classBaseName(string $file): ?string
    {
        $basename = pathinfo($file, PATHINFO_FILENAME);
        if ($basename === '' || $basename === '.') {
            return null;
        }

        $basename = preg_replace('/Controller$/', '', $basename) ?? $basename;
        $basename = preg_replace('/Service$/', '', $basename) ?? $basename;
        $basename = preg_replace('/Repository$/', '', $basename) ?? $basename;

        return $basename;
    }

    private function modelHasCustomLogic(string $file): bool
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return false;
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return false;
        }

        $methods = $this->finder()->findInstanceOf($ast, \PhpParser\Node\Stmt\ClassMethod::class);

        return count($methods) >= 3;
    }

    /**
     * @param list<string> $files
     * @return array<string, true>
     */
    private function collectTestNames(array $files): array
    {
        $names = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $normalized = str_replace('\\', '/', $file);
            if (!str_contains($normalized, '/tests/') && !str_starts_with($normalized, 'tests/')) {
                continue;
            }

            $names[pathinfo($file, PATHINFO_FILENAME)] = true;
        }

        return $names;
    }
}
