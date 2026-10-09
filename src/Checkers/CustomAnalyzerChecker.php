<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Checkers;

use Rampart\QualityChecker\Analyzers\Convention\DeadCodeAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\LaravelPitfallAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\NamingConventionAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\TodoFixmeAnalyzer;
use Rampart\QualityChecker\Analyzers\Frontend\BladeStackAnalyzer;
use Rampart\QualityChecker\Analyzers\Frontend\CssSyntaxAnalyzer;
use Rampart\QualityChecker\Analyzers\Frontend\JsSyntaxAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\EolAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\PermsAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\ObfuscatedAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\RoguePhpAnalyzer;
use Rampart\QualityChecker\Analyzers\Deduplicator;
use Rampart\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use Rampart\QualityChecker\Analyzers\Laravel\RouteValidationAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspOwnershipAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\AuthHardeningAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\DisabledCsrfAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\InsecureCookieAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\LaravelTaintAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\MassAssignmentAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\SqlInjectionAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\Taint\TaintEngine;
use Rampart\QualityChecker\Analyzers\Security\UnsafeDeserializationAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\UnsafeEvalAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\ControllerTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\FeatureTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\MissingTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\TestCoverageAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\TestWithoutAssertAnalyzer;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Semantic\OwnershipShadow;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Scanning\PathExcluder;
use Rampart\QualityChecker\Scanning\ScanContext;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Suppression\InlineSuppressor;

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
        Profiler::enableFromEnvironment();
        if ($ctx->profile) {
            Profiler::setEnabled(true);
        }
        Profiler::begin('discovery');
        [$files, $skippedOversized, $skippedExcluded] = $this->collectFiles($ctx);
        $files = array_values(array_unique(array_merge(
            $files,
            $this->collectBladeFiles($ctx),
            $this->collectJsFiles($ctx),
            $this->collectCssFiles($ctx),
            $this->collectEnvFiles($ctx)
        )));
        Profiler::end('discovery');
        $issues = [];
        OwnershipShadow::reset();

        // One shared scan context per run: source read once, AST parsed
        // once, failures cached (canonical AST contract — see
        // ScanContext). GC is parked for the analyzer loop: canonical
        // trees carry parent links (node cycles) and are retained by
        // design until the run ends, so the collector would rescan a
        // growing cyclic graph on every threshold trip (~2x wall time,
        // zero bytes freed). Refcount still frees analyzer temporaries;
        // GC resumes in the finally below. VV_NO_GC_PARK=1 skips parking
        // for the PERF-EVAL-2 GC A/B experiment.
        $scan = new ScanContext();
        // Analyzers that resolve project-relative paths (routes/, tests/) read
        // the root from here instead of guessing getcwd(). Without it, pointing
        // this tool at another project inspected the caller's directories.
        $scan->setBasePath($ctx->basePath);
        $parkGc = getenv('VV_NO_GC_PARK') !== '1';
        if ($parkGc) {
            gc_disable();
        }
        try {
            foreach ($this->buildAnalyzers($ctx) as $entry) {
                if (!$entry['enabled']) {
                    continue;
                }

                $analyzer = $entry['analyzer'];
                if ($analyzer instanceof ScanContextAware) {
                    $analyzer->setScanContext($scan);
                }
                $issues = array_merge($issues, $this->runAnalyzer($analyzer, $files));
            }
        } finally {
            if ($parkGc) {
                gc_enable();
            }
        }
        $stats = $scan->stats();
        Profiler::gauge('scan_source_requests', $stats['source_requests']);
        Profiler::gauge('scan_source_hits', $stats['source_hits']);
        Profiler::gauge('scan_ast_requests', $stats['ast_requests']);
        Profiler::gauge('scan_ast_hits', $stats['ast_hits']);
        Profiler::gauge('scan_ast_misses', $stats['ast_misses']);
        Profiler::gauge('scan_parse_failures', $stats['parse_failures']);
        Profiler::gauge('scan_files', $stats['files']);

        if ($this->taintEnabled($ctx)) {
            $issues = array_merge($issues, $this->runTaintEngine($files));
        }

        $issues = (new Deduplicator())->dedupeList($issues);

        $issues = $this->reconcileOwnership($issues);

        $issues = $this->applySeverityOverrides($issues, $ctx);

        $suppressed = 0;
        if ($this->inlineSuppressionEnabled($ctx)) {
            $suppressor = new InlineSuppressor();
            $issues = $suppressor->filter($issues);
            $suppressed = $suppressor->countSuppressed();
        }

        // The resolved context value, not config['min_confidence'] read directly: the
        // CLI flag and the config key are the same setting, and reading only the
        // config meant `--min-confidence=high` still listed every low-confidence
        // finding while the report header and the gate both said "high".
        $minConfidence = Confidence::fromString(
            $ctx->minConfidence !== ''
                ? $ctx->minConfidence
                : (string) ($ctx->config['min_confidence'] ?? 'low')
        );
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
        if ($skippedExcluded > 0) {
            $summary .= sprintf(' %d file(s) excluded by analyzers.exclude_paths.', $skippedExcluded);
        }

        return new CheckResult($this->name(), $status, microtime(true) - $start, $issues, null, $summary);
    }

    /**
     * v0.6.2 BAC/ownership reconciliation. Identity is file +
     * controller + action (both analyzers record the same keys):
     * - An ownership issue on an action that already has a BAC finding
     *   merges INTO the BAC finding (full chain preserved under
     *   access_control.ownership) instead of a second issue.
     * - A BAC finding with a shadow decision but no ownership issue is
     *   enriched with the decision (PROTECTED proof, weak REVIEW
     *   context, or UNKNOWN limitation) — provenance without verdict
     *   change.
     * - Ownership issues with no BAC counterpart survive (the deleteLink
     *   false-negative class BAC never flagged).
     *
     * @param Issue[] $issues
     * @return Issue[]
     */
    private function reconcileOwnership(array $issues): array
    {
        $decisions = OwnershipShadow::all();
        if ($decisions === []) {
            return $issues;
        }
        $byAction = [];
        foreach ($decisions as $decision) {
            $byAction[$this->ownershipIdentity($decision->file, $decision->controller, $decision->method)] = $decision;
        }

        $bacIndex = [];
        foreach ($issues as $i => $issue) {
            if ($issue->rule !== OwaspAccessControlAnalyzer::RULE) {
                continue;
            }
            $controller = (string) ($issue->metadata['controller'] ?? '');
            $action = (string) ($issue->metadata['action'] ?? ($issue->metadata['method'] ?? ''));
            if ($controller === '' || $action === '') {
                continue;
            }
            $bacIndex[$this->ownershipIdentity((string) $issue->file, $controller, $action)] = $i;
        }

        $merged = 0;
        $enriched = 0;
        $drop = [];
        foreach ($issues as $i => $issue) {
            if ($issue->rule !== OwaspOwnershipAnalyzer::RULE) {
                continue;
            }
            $controller = (string) ($issue->metadata['controller'] ?? '');
            $action = (string) ($issue->metadata['action'] ?? '');
            $key = $this->ownershipIdentity((string) $issue->file, $controller, $action);
            if (!isset($bacIndex[$key])) {
                continue;
            }
            $bac = $issues[$bacIndex[$key]];
            $bac->metadata['access_control']['ownership'] = $issue->metadata['access_control']['ownership'] ?? [];
            $bac->metadata['access_control']['ownership_merged'] = true;
            $drop[$i] = true;
            ++$merged;
        }
        if ($drop !== []) {
            $issues = array_values(array_filter(
                $issues,
                static fn (Issue $issue, int $i): bool => !isset($drop[$i]),
                ARRAY_FILTER_USE_BOTH
            ));
        }
        foreach ($issues as $issue) {
            if ($issue->rule !== OwaspAccessControlAnalyzer::RULE) {
                continue;
            }
            $controller = (string) ($issue->metadata['controller'] ?? '');
            $action = (string) ($issue->metadata['action'] ?? ($issue->metadata['method'] ?? ''));
            $key = $this->ownershipIdentity((string) $issue->file, $controller, $action);
            if (!isset($byAction[$key]) || isset($issue->metadata['access_control']['ownership'])) {
                continue;
            }
            $issue->metadata['access_control']['ownership'] = $byAction[$key]->toArray();
            ++$enriched;
        }
        Profiler::gauge('ownership_merged', $merged);
        Profiler::gauge('bac_ownership_enriched', $enriched);

        return array_values($issues);
    }

    private function ownershipIdentity(string $file, string $controller, string $action): string
    {
        return strtolower($file . '|' . ltrim($controller, '\\') . '@' . $action);
    }

    /**
 * Per-rule severity remapping, applied after analysis and before the
 * confidence filter so the gate sees the reported severity.
 *
 * The blade rules default to 'info' because they dominate finding counts on
 * real projects (~1,000 of 7,000 across the 27-project benchmark) while the
 * overwhelming majority are `{!! $model->field !!}` renderings that Blade
 * templates use deliberately. At 'error' they made a default run red before a
 * user had seen anything.
 *
 * This is a config knob and not a change to the analyzer: `OWASP_BLADE_XSS` at
 * 'error' fires only for request-derived output, which is reflected XSS and
 * does deserve to fail a gate. Demoting it to 'info' therefore stops
 * `--tier=security` from catching reflected XSS, so a project that wants that
 * back sets `'OWASP_BLADE_XSS' => 'error'` (or 'critical') explicitly.
 *
 * @param Issue[] $issues
 * @return Issue[]
 */
    private function applySeverityOverrides(array $issues, CheckContext $ctx): array
    {
        $overrides = $ctx->config['analyzers']['severity_overrides'] ?? [];
        if (!is_array($overrides) || $overrides === []) {
            return $issues;
        }

        $map = [];
        foreach ($overrides as $rule => $severity) {
            if (!is_string($rule) || !is_string($severity)) {
                continue;
            }
            // fromString() falls back to Error on a typo, which would silently
            // promote a rule; an unparseable value is a config error, so skip
            // the rule instead of guessing a direction.
            if (Severity::tryFrom(strtolower($severity)) === null) {
                continue;
            }
            $map[strtoupper($rule)] = Severity::fromString($severity);
        }

        if ($map === []) {
            return $issues;
        }

        foreach ($issues as $issue) {
            $override = $map[strtoupper($issue->rule)] ?? null;
            if ($override !== null) {
                $issue->severity = $override;
            }
        }

        return $issues;
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
            $this->entry($analyzers, 'owasp.ownership_idor', new OwaspOwnershipAnalyzer()),
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
            $this->entry($analyzers, 'frontend.js_syntax', new JsSyntaxAnalyzer()),
            $this->entry($analyzers, 'frontend.css_syntax', new CssSyntaxAnalyzer()),
            $this->entry($analyzers, 'frontend.blade_stack', new BladeStackAnalyzer()),
            $this->entry($analyzers, 'ops.perms', new PermsAnalyzer()),
            $this->entry($analyzers, 'ops.eol', new EolAnalyzer()),
            $this->entry($analyzers, 'security.rogue_php', new RoguePhpAnalyzer()),
            $this->entry($analyzers, 'security.obfuscated', new ObfuscatedAnalyzer()),
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
        $fqcn = get_class($analyzer);
        $short = substr((string) strrchr($fqcn, '\\'), 1) ?: $fqcn;
        Profiler::countFilesVisited($short, count($files));

        $issues = Profiler::timeAnalyzer($short, static function () use ($analyzer, $files): array {
            $issues = [];
            foreach ($analyzer->analyze($files) as $issue) {
                if ($issue instanceof Issue) {
                    $issues[] = $issue;
                }
            }

            return $issues;
        });
        Profiler::countIssues($short, count($issues));

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
     * are always honored. Returns [files, oversizedSkipped, excludedSkipped].
     *
     * @return array{list<string>, int, int}
     */
    private function collectFiles(CheckContext $ctx): array
    {
        $files = [];
        $skippedOversized = 0;
        $skippedExcluded = 0;
        $skipDirs = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git'];
        $maxBytes = $this->maxFileBytes($ctx);
        $excluder = PathExcluder::fromConfig($ctx->config);

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
                if (!$excluder->isEmpty() && $excluder->excludes($pathname)) {
                    $skippedExcluded++;
                    continue;
                }
                if ($maxBytes > 0 && $file->getSize() > $maxBytes) {
                    $skippedOversized++;
                    continue;
                }

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

        return [array_values(array_unique($files)), $skippedOversized, $skippedExcluded];
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
     * The vendor/node_modules guard matters here as much as in the other
     * collectors: `$ctx->resolvePath()` is relative to the app root, and a
     * Testbench-based consumer (or any project whose base path sits inside
     * vendor) otherwise gets an unrelated `.env.example` from a dependency
     * analysed as if it were the app's own config.
     *
     * @return list<string>
     */
    private function collectEnvFiles(CheckContext $ctx): array
    {
        $files = [];
        $excluder = PathExcluder::fromConfig($ctx->config);
        foreach (['.env', '.env.example'] as $name) {
            $abs = $ctx->resolvePath($name);
            if (!is_file($abs)) {
                continue;
            }
            $normalized = str_replace('\\', '/', $abs);
            if (str_contains($normalized, '/vendor/') || str_contains($normalized, '/node_modules/')) {
                continue;
            }
            if (!$excluder->excludes($normalized)) {
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

        $excluder = PathExcluder::fromConfig($ctx->config);
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
            if ($excluder->excludes($pathname)) {
                continue;
            }
            $files[] = $file->getPathname();
        }

        return array_values(array_unique($files));
    }

    /**
     * JS/TS files — collected separately so only JS-aware analyzers consume them.
     *
     * @return list<string>
     */
    private function collectJsFiles(CheckContext $ctx): array
    {
        $roots = ['resources', 'public'];
        $files = [];
        $excluder = PathExcluder::fromConfig($ctx->config);
        foreach ($roots as $root) {
            $abs = $ctx->resolvePath($root);
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
                $ext = strtolower($file->getExtension());
                if (!in_array($ext, ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue'], true)) {
                    continue;
                }
                $pathname = str_replace('\\', '/', $file->getPathname());
                if (str_contains($pathname, '/vendor/') || str_contains($pathname, '/node_modules/')) {
                    continue;
                }
                if ($excluder->excludes($pathname)) {
                    continue;
                }
                $files[] = $file->getPathname();
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * CSS/SCSS files.
     *
     * @return list<string>
     */
    private function collectCssFiles(CheckContext $ctx): array
    {
        $roots = ['resources', 'public'];
        $files = [];
        $excluder = PathExcluder::fromConfig($ctx->config);
        foreach ($roots as $root) {
            $abs = $ctx->resolvePath($root);
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
                $ext = strtolower($file->getExtension());
                if (!in_array($ext, ['css', 'scss', 'sass', 'less'], true)) {
                    continue;
                }
                $pathname = str_replace('\\', '/', $file->getPathname());
                if (str_contains($pathname, '/vendor/') || str_contains($pathname, '/node_modules/')) {
                    continue;
                }
                if ($excluder->excludes($pathname)) {
                    continue;
                }
                $files[] = $file->getPathname();
            }
        }

        return array_values(array_unique($files));
    }
}
