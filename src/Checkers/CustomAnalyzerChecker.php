<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use VietVang\QualityChecker\Analyzers\Convention\DeadCodeAnalyzer;
use VietVang\QualityChecker\Analyzers\Convention\LaravelPitfallAnalyzer;
use VietVang\QualityChecker\Analyzers\Convention\NamingConventionAnalyzer;
use VietVang\QualityChecker\Analyzers\Convention\TodoFixmeAnalyzer;
use VietVang\QualityChecker\Analyzers\Deduplicator;
use VietVang\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use VietVang\QualityChecker\Analyzers\Laravel\RouteValidationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\DisabledCsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\LaravelTaintAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\MassAssignmentAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\SqlInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\Taint\TaintEngine;
use VietVang\QualityChecker\Analyzers\Security\UnsafeDeserializationAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\UnsafeEvalAnalyzer;
use VietVang\QualityChecker\Analyzers\TestCoverage\ControllerTestAnalyzer;
use VietVang\QualityChecker\Analyzers\TestCoverage\FeatureTestAnalyzer;
use VietVang\QualityChecker\Analyzers\TestCoverage\MissingTestAnalyzer;
use VietVang\QualityChecker\Analyzers\TestCoverage\TestCoverageAnalyzer;
use VietVang\QualityChecker\Analyzers\TestCoverage\TestWithoutAssertAnalyzer;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class CustomAnalyzerChecker implements CheckerInterface
{
    public function name(): string
    {
        return 'custom';
    }

    public function description(): string
    {
        return 'Custom analyzers: security (OWASP + taint), missing test coverage, conventions.';
    }

    public function config(): array
    {
        return [
            'enabled' => true,
        ];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        $config = $ctx->config['analyzers'] ?? [];

        return (bool) ($config['enabled'] ?? true);
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $files = $this->collectFiles($ctx);
        $issues = [];

        foreach ($this->buildAnalyzers($ctx) as $entry) {
            if (!$entry['enabled']) {
                continue;
            }

            $issues = array_merge($issues, $this->runAnalyzer($entry['analyzer'], $files));
        }

        if ($this->taintEnabled($ctx)) {
            $issues = array_merge($issues, $this->runTaintEngine($files));
        }

        $issues = (new Deduplicator())->dedupeList($issues);

        $minConfidence = Confidence::fromString((string) ($ctx->config['min_confidence'] ?? 'low'));
        $issues = array_values(array_filter(
            $issues,
            static fn (Issue $issue): bool => $issue->confidence->intValue() >= $minConfidence->intValue()
        ));

        $status = 'passed';
        foreach ($issues as $issue) {
            if ($issue->severity === Severity::Error || $issue->severity === Severity::Critical) {
                $status = 'failed';
                break;
            }
            $status = 'warning';
        }

        $summary = sprintf('Custom analyzers found %d issue(s) across %d file(s).', count($issues), count($files));

        return new CheckResult($this->name(), $status, microtime(true) - $start, $issues, null, $summary);
    }

    /**
     * @return array<int, array{enabled: bool, analyzer: object}>
     */
    private function buildAnalyzers(CheckContext $ctx): array
    {
        $analyzers = $ctx->config['analyzers'] ?? [];

        return [
            $this->entry($analyzers, 'security.sql_injection', new SqlInjectionAnalyzer()),
            $this->entry($analyzers, 'security.unsafe_eval', new UnsafeEvalAnalyzer()),
            $this->entry($analyzers, 'security.hardcoded_secret', new HardcodedSecretAnalyzer()),
            $this->entry($analyzers, 'security.mass_assignment', new MassAssignmentAnalyzer()),
            $this->entry($analyzers, 'security.unsafe_unserialize', new UnsafeDeserializationAnalyzer()),
            $this->entry($analyzers, 'security.insecure_hash', new InsecureHashAnalyzer()),
            $this->entry($analyzers, 'security.laravel_taint', new LaravelTaintAnalyzer()),
            $this->entry($analyzers, 'security.disabled_csrf', new DisabledCsrfAnalyzer()),
            $this->entry($analyzers, 'owasp.broken_access_control', new OwaspAccessControlAnalyzer()),
            $this->entry($analyzers, 'owasp.ssrf', new OwaspSsrfAnalyzer()),
            $this->entry($analyzers, 'owasp.ssti', new OwaspSstiAnalyzer()),
            $this->entry($analyzers, 'owasp.misconfiguration', new OwaspMisconfigurationAnalyzer()),
            $this->entry($analyzers, 'owasp.command_injection', new OwaspCommandInjectionAnalyzer()),
            $this->entry($analyzers, 'owasp.xxe', new OwaspXxeAnalyzer()),
            $this->entry($analyzers, 'laravel.migration', new MigrationAnalyzer()),
            $this->entry($analyzers, 'laravel.route_validation', new RouteValidationAnalyzer()),
            $this->entry($analyzers, 'test_coverage.missing_controller_test', new ControllerTestAnalyzer()),
            $this->entry($analyzers, 'test_coverage.missing_service_test', new MissingTestAnalyzer(['services', 'repositories'])),
            $this->entry($analyzers, 'test_coverage.missing_model_test', new MissingTestAnalyzer(['models'])),
            $this->entry($analyzers, 'test_coverage.missing_feature_coverage', new FeatureTestAnalyzer()),
            $this->entry($analyzers, 'test_coverage.test_without_assert', new TestWithoutAssertAnalyzer()),
            $this->entry($analyzers, 'test_coverage.unified', new TestCoverageAnalyzer()),
            $this->entry($analyzers, 'convention.naming_convention', new NamingConventionAnalyzer()),
            $this->entry($analyzers, 'convention.todo_fixme', new TodoFixmeAnalyzer()),
            $this->entry($analyzers, 'convention.dead_code', new DeadCodeAnalyzer()),
            $this->entry($analyzers, 'convention.laravel_pitfall', new LaravelPitfallAnalyzer()),
        ];
    }

    /**
     * @return array{enabled: bool, analyzer: object}
     */
    private function entry(array $analyzers, string $key, object $analyzer): array
    {
        $parts = explode('.', $key);
        $group = $parts[0];
        $rule = $parts[1];

        $enabled = (bool) ($analyzers[$group][$rule] ?? false);

        return ['enabled' => $enabled, 'analyzer' => $analyzer];
    }

    /**
     * @param list<string> $files
     * @return Issue[]
     */
    private function runAnalyzer(object $analyzer, array $files): array
    {
        $issues = [];
        foreach ($analyzer->analyze($files) as $issue) {
            if ($issue instanceof Issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function taintEnabled(CheckContext $ctx): bool
    {
        return (bool) ($ctx->config['analyzers']['security']['taint_engine'] ?? false);
    }

    /**
     * @param list<string> $files
     * @return Issue[]
     */
    private function runTaintEngine(array $files): array
    {
        $issues = [];
        $engine = new TaintEngine();
        foreach ($engine->analyze($files) as $raw) {
            if (is_array($raw)) {
                $issues[] = Issue::fromArray($raw);
            }
        }

        return $issues;
    }

    /**
     * @return list<string>
     */
    private function collectFiles(CheckContext $ctx): array
    {
        $files = [];
        $skipDirs = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git'];

        foreach ($ctx->paths as $path) {
            $abs = $ctx->resolvePath($path);

            if (is_file($abs)) {
                if (strtolower((string) pathinfo($abs, PATHINFO_EXTENSION)) === 'php') {
                    $files[] = $abs;
                }
                continue;
            }

            if (!is_dir($abs)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($abs, \FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                $extension = strtolower($file->getExtension());
                if ($extension !== 'php') {
                    continue;
                }

                $pathname = str_replace('\\', '/', $file->getPathname());
                $skipped = false;
                foreach ($skipDirs as $skipDir) {
                    if (str_contains($pathname, '/' . $skipDir . '/')) {
                        $skipped = true;
                        break;
                    }
                }
                if (!$skipped) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return array_values(array_unique($files));
    }
}
