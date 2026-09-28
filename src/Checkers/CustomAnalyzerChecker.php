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
use VietVang\QualityChecker\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\AuthHardeningAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\DisabledCsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\InsecureCookieAnalyzer;
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
use VietVang\QualityChecker\Suppression\InlineSuppressor;

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
        [$files, $skippedOversized] = $this->collectFiles($ctx);
        $files = array_values(array_unique(array_merge(
            $files,
            $this->collectBladeFiles($ctx),
            $this->collectEnvFiles($ctx)
        )));
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

        $suppressed = 0;
        if ($this->inlineSuppressionEnabled($ctx)) {
            $suppressor = new InlineSuppressor();
            $issues = $suppressor->filter($issues);
            $suppressed = $suppressor->countSuppressed();
        }

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
        if ($suppressed > 0) {
            $summary .= sprintf(' %d issue(s) suppressed via inline ignore.', $suppressed);
        }
        if ($skippedOversized > 0) {
            $summary .= sprintf(' %d oversized file(s) skipped (see max_file_kb).', $skippedOversized);
        }

        return new CheckResult($this->name(), $status, microtime(true) - $start, $issues, null, $summary);
    }

    private function inlineSuppressionEnabled(CheckContext $ctx): bool
    {
        $analyzers = $ctx->config['analyzers'] ?? [];

        return (bool) ($analyzers['inline_suppression'] ?? true);
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
            $this->entry($analyzers, 'security.mass_assignment', new MassAssignmentAnalyzer(
                ['models_dirs' => $analyzers['models_dirs'] ?? ['app/Models']]
            )),
            $this->entry($analyzers, 'security.unsafe_unserialize', new UnsafeDeserializationAnalyzer()),
            $this->entry($analyzers, 'security.insecure_hash', new InsecureHashAnalyzer()),
            $this->entry($analyzers, 'security.insecure_cookie', new InsecureCookieAnalyzer()),
            $this->entry($analyzers, 'security.auth_hardening', new AuthHardeningAnalyzer()),
            $this->entry($analyzers, 'security.laravel_taint', new LaravelTaintAnalyzer()),
            $this->entry($analyzers, 'security.disabled_csrf', new DisabledCsrfAnalyzer()),
            $this->entry($analyzers, 'owasp.broken_access_control', new OwaspAccessControlAnalyzer(
                (bool) ($analyzers['owasp']['route_middleware'] ?? true),
                ['extra_middleware' => $analyzers['extra_middleware'] ?? []]
            )),
            $this->entry($analyzers, 'owasp.blade_xss', new OwaspBladeXssAnalyzer(
                ['extra_sanitizers' => $analyzers['extra_sanitizers'] ?? []]
            )),
            $this->entry($analyzers, 'owasp.open_redirect', new OwaspOpenRedirectAnalyzer()),
            $this->entry($analyzers, 'owasp.path_traversal', new OwaspPathTraversalAnalyzer()),
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
     * PHP files under the scan paths. Files larger than max_file_kb are
     * skipped: multi-megabyte data dumps (e.g. a 2.4 MB SMS-number list)
     * exhaust the parser with zero security signal. Explicitly-passed files
     * are always honored. Returns [files, oversizedSkipped].
     *
     * @return array{list<string>, int}
     */
    private function collectFiles(CheckContext $ctx): array
    {
        $files = [];
        $skippedOversized = 0;
        $skipDirs = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git'];
        $maxBytes = $this->maxFileBytes($ctx);

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
                if ($maxBytes > 0 && $file->getSize() > $maxBytes) {
                    $skippedOversized++;
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

        return [array_values(array_unique($files)), $skippedOversized];
    }

    private function maxFileBytes(CheckContext $ctx): int
    {
        $kb = (int) ($ctx->config['analyzers']['max_file_kb'] ?? 1024);
        if ($kb <= 0) {
            return 0;
        }

        return $kb * 1024;
    }

    /**
     * Root-level `.env` files, collected separately (like blade views) so only
     * env-aware analyzers consume them.
     *
     * @return list<string>
     */
    private function collectEnvFiles(CheckContext $ctx): array
    {
        $files = [];
        foreach (['.env', '.env.example'] as $name) {
            $abs = $ctx->resolvePath($name);
            if (is_file($abs)) {
                $files[] = $abs;
            }
        }

        return $files;
    }

    /**
     * Blade views live under `resources/` which is not part of the default scan
     * paths (phpcs/phpstan must not lint templates). Collected separately so
     * only blade-aware analyzers consume them — every other analyzer filters
     * by `.php` in `supports()`.
     *
     * @return list<string>
     */
    private function collectBladeFiles(CheckContext $ctx): array
    {
        $files = [];
        $abs = $ctx->resolvePath('resources');
        if (!is_dir($abs)) {
            return $files;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($abs, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            if (!str_ends_with(strtolower($file->getFilename()), '.blade.php')) {
                continue;
            }

            $pathname = str_replace('\\', '/', $file->getPathname());
            if (
                str_contains($pathname, '/vendor/')
                || str_contains($pathname, '/node_modules/')
                || str_contains($pathname, '/storage/')
            ) {
                continue;
            }
            $files[] = $file->getPathname();
        }

        return array_values(array_unique($files));
    }
}
