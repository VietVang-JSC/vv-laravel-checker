<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Commands;

use Illuminate\Console\Command;
use Rampart\QualityChecker\Baseline\BaselineFilter;
use Rampart\QualityChecker\Baseline\BaselineManager;
use Rampart\QualityChecker\Baseline\IssueDelta;
use Rampart\QualityChecker\Fixer\PhpcsFixer;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Reporters\ConsoleReporter;
use Rampart\QualityChecker\Reporters\HtmlReporter;
use Rampart\QualityChecker\Reporters\JsonReporter;
use Rampart\QualityChecker\Reporters\MarkdownReporter;
use Rampart\QualityChecker\Reporters\ReporterInterface;
use Rampart\QualityChecker\Reporters\SarifReporter;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\PackageVersion;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Runner\CheckRunner;

final class QualityCheckCommand extends Command
{
    protected $signature = 'quality:check
        {--format=console : Comma-separated report formats: console,json,html,md,sarif or "all".}
        {--only= : Only run these checkers (comma-separated): phpcs,phpstan,phpunit,composer_audit,trivy,custom.}
        {--exclude= : Skip these checkers (comma-separated).}
        {--ignore= : Skip these rules (comma-separated, e.g. MISSING_MODEL_TEST).}
        {--path=* : Override scan paths (repeatable).}
        {--exclude-path=* : Skip files matching these path patterns, e.g. */fixtures/* (repeatable, merged with analyzers.exclude_paths).}
        {--fail-on=error : Fail threshold: none|info|warning|error|critical.}
        {--tier= : Quality gate tier: security|quality|all (default: config tier).}
        {--min-confidence= : Minimum confidence to report: low|medium|high.}
        {--output= : Output directory for report files.}
        {--no-cache : Ignore cached analyzer/checker results.}
        {--no-auto-install : Disable auto-installing missing tools (phpcs/phpstan/phpunit/trivy).}
        {--json : Shortcut for --format=json.}
        {--ci : CI mode: json output, fail-on=error, no progress.}
        {--fix : Auto-fix fixable issues (currently phpcbf only).}
        {--baseline-generate : Write current issues to the baseline file.}
        {--baseline-update : Rewrite baseline with all current issues.}
        {--baseline-file= : Baseline file path (default: baseline.json in project root).}
        {--profile : Emit a machine-readable profiler report (timers, parse/file-visit amplification). Findings unchanged.}';

    protected $description = 'Run the Laravel quality gate: phpcs, phpstan, phpunit, dependency audit, security & convention analyzers.';

    public function handle(): int
    {
        try {
            $ctx = $this->buildContext();
        } catch (\Throwable $e) {
            $this->error('Failed to build check context: ' . $e->getMessage());

            return 2;
        }

        $runner = new CheckRunner($ctx);
        $checkers = $runner->buildCheckers();
        $results = $runner->run($checkers);

        $this->recordDelta($ctx, $results);

        $results = $this->applyBaseline($ctx, $results);

        if ($ctx->fix) {
            $this->runFixer($ctx);
        }

        $ctx->exitCode = $runner->shouldFail($results) ? 1 : 0;

        $this->render($results, $ctx);

        if ($ctx->profile) {
            $this->writeProfileReport($ctx);
        }

        return $ctx->exitCode;
    }

    /**
     * Machine-readable profiler report (PERF-EVAL-1). Emitted only with
     * --profile; never affects findings.
     */
    private function writeProfileReport(CheckContext $ctx): void
    {
        $report = Profiler::report();
        $path = rtrim($ctx->outputDir, '/\\') . DIRECTORY_SEPARATOR . 'profile.json';
        if (!is_dir($ctx->outputDir)) {
            @mkdir($ctx->outputDir, 0777, true);
        }
        file_put_contents($path, json_encode($report, JSON_PRETTY_PRINT));
        $this->line(sprintf('Profiler report written to %s.', $path));
    }

    private function buildContext(): CheckContext
    {
        $config = (array) config('quality-checker');

        $basePath = function_exists('base_path') ? (string) base_path() : (string) getcwd();

        $paths = $this->option('path');
        if (!is_array($paths) || count($paths) === 0) {
            $paths = (array) ($config['paths'] ?? ['app', 'routes', 'database', 'config', 'tests']);
        }
        $paths = array_values(array_filter($paths, static fn ($p): bool => is_string($p) && $p !== ''));

        // Path exclusion for the custom analyzers: config default plus
        // --exclude-path. Merged rather than replaced so a one-off CLI run
        // cannot accidentally un-exclude the project-wide fixtures.
        $excludePaths = $config['analyzers']['exclude_paths'] ?? [];
        if (!is_array($excludePaths)) {
            $excludePaths = [];
        }
        $cliExcludePaths = $this->option('exclude-path');
        if (is_array($cliExcludePaths)) {
            $excludePaths = array_merge($excludePaths, $cliExcludePaths);
        }
        if ($excludePaths !== []) {
            $analyzers = $config['analyzers'] ?? [];
            $analyzers = is_array($analyzers) ? $analyzers : [];
            $analyzers['exclude_paths'] = array_values(array_unique(array_map('strval', $excludePaths)));
            $config['analyzers'] = $analyzers;
        }

        $failOn = (string) $this->option('fail-on');
        if ($this->option('ci') && $failOn === 'error') {
            $failOn = 'error';
        }

        $outputDir = (string) $this->option('output');
        if ($outputDir === '') {
            $outputDir = (string) ($config['output_dir'] ?? 'reports/quality-checker');
        }
        $outputDir = $this->resolveOutputDir($basePath, $outputDir);

        $format = $this->resolveFormat();

        $only = $this->splitOption('only');
        $exclude = $this->splitOption('exclude');

        // Rule-level ignore: config quality_gate.ignore plus --ignore=.
        $gate = $config['quality_gate'] ?? [];
        if (!is_array($gate)) {
            $gate = [];
        }
        $gateIgnore = $gate['ignore'] ?? [];
        if (!is_array($gateIgnore)) {
            $gateIgnore = [];
        }
        $gate['ignore'] = array_values(array_unique(array_merge(
            array_map('strval', $gateIgnore),
            $this->splitOption('ignore')
        )));
        $config['quality_gate'] = $gate;

        $packageVersion = PackageVersion::detect();

        $ctx = new CheckContext(
            $basePath,
            $paths,
            $config,
            $outputDir,
            noCache: (bool) $this->option('no-cache'),
            ci: (bool) $this->option('ci'),
            quiet: (bool) $this->option('quiet'),
            packageVersion: $packageVersion,
            failOn: $failOn,
            only: $only,
            exclude: $exclude,
            tier: (string) ($this->option('tier') ?: $config['tier'] ?? 'quality'),
            minConfidence: (string) ($this->option('min-confidence') ?: $config['min_confidence'] ?? 'low'),
            noAutoInstall: (bool) $this->option('no-auto-install'),
        );

        $ctx->fix = (bool) $this->option('fix');
        $ctx->profile = (bool) $this->option('profile');

        $baselineFile = $this->option('baseline-file');
        if (is_string($baselineFile) && $baselineFile !== '') {
            $ctx->baselineFile = $baselineFile;
        } else {
            $ctx->baselineFile = $basePath . DIRECTORY_SEPARATOR . 'baseline.json';
        }

        $ctx->metadata = ['format' => $format];

        return $ctx;
    }

    /**
     * PR-style delta vs the baseline file (New / Fixed / Existing), stored
     * on the context for reporters. Computed before baseline filtering so
     * the "existing" count survives. Only when a baseline file exists and
     * we are not (re)generating it.
     *
     * @param CheckResult[] $results
     */
    private function recordDelta(CheckContext $ctx, array $results): void
    {
        if (!is_file($ctx->baselineFile)) {
            return;
        }
        try {
            $generate = (bool) $this->option('baseline-generate');
            $update = (bool) $this->option('baseline-update');
        } catch (\Throwable $e) {
            return;
        }
        if ($generate || $update) {
            return;
        }

        $manager = new BaselineManager($ctx->baselineFile);
        $manager->load();

        $issues = [];
        foreach ($this->resultsToArrays($results) as $result) {
            foreach ($result['issues'] ?? [] as $issue) {
                $issues[] = $issue;
            }
        }

        $delta = IssueDelta::compute($issues, $manager->signatures());
        $ctx->metadata['delta'] = [
            'new' => count($delta['new']),
            'fixed' => $delta['fixed'],
            'existing' => $delta['existing'],
            'new_by_rule' => $delta['new_by_rule'],
        ];

        $this->line(sprintf(
            'Delta vs baseline: %d new, %d fixed, %d existing.',
            count($delta['new']),
            $delta['fixed'],
            $delta['existing']
        ));
    }

    /**
     * @param CheckResult[] $results
     * @return CheckResult[]
     */
    private function applyBaseline(CheckContext $ctx, array $results): array
    {
        $generate = (bool) $this->option('baseline-generate');
        $update = (bool) $this->option('baseline-update');

        if (!$generate && !$update && !is_file($ctx->baselineFile)) {
            return $results;
        }

        $manager = new BaselineManager($ctx->baselineFile);

        if ($generate || $update) {
            $manager->update($this->resultsToArrays($results), $ctx->baselineFile);
            $this->line(sprintf('Baseline %s written to %s.', $update ? 'updated' : 'generated', $ctx->baselineFile));
        } else {
            $manager->load();
            $filter = new BaselineFilter($manager);
            $filtered = $filter->filter($this->resultsToArrays($results));
            $baselined = $filter->countBaselined();
            if ($baselined > 0) {
                $this->line(sprintf('<fg=yellow>%d known issue(s) excluded via baseline.</>', $baselined));
            }

            $results = $this->arraysToResults($filtered);
        }

        return $results;
    }

    private function runFixer(CheckContext $ctx): void
    {
        $fixer = new PhpcsFixer();
        $config = $ctx->configFor('phpcs', ['standard' => 'PSR12']);
        $standard = (string) ($config['standard'] ?? 'PSR12');

        if (!$fixer->isAvailable($ctx)) {
            $this->warn('phpcbf not found — cannot auto-fix. Install squizlabs/php_codesniffer.');

            return;
        }

        $this->line('<fg=cyan>Running phpcbf auto-fix...</>');
        $fixResult = $fixer->fix($ctx->paths, $standard);

        if (!$fixResult->success()) {
            $this->warn('phpcbf reported errors: ' . implode('; ', $fixResult->errors));

            return;
        }

        $this->line(sprintf('<fg=green>phpcbf: %d file(s) fixed.</>', $fixResult->filesFixed));
    }

    /**
     * @param CheckResult[] $results
     */
    private function render(array $results, CheckContext $ctx): void
    {
        $formats = $ctx->metadata['format'] ?? ['console'];

        foreach ($formats as $format) {
            $reporter = $this->reporterFor($format);
            if ($reporter !== null) {
                $reporter->render($results, $ctx);
            }
        }
    }

    private function reporterFor(string $format): ?ReporterInterface
    {
        return match ($format) {
            'console' => new ConsoleReporter($this->output),
            'json' => new JsonReporter(),
            'html' => new HtmlReporter(),
            'md' => new MarkdownReporter(),
            'sarif' => new SarifReporter(),
            default => null,
        };
    }

    /**
     * @return list<string>
     */
    private function resolveFormat(): array
    {
        $formats = [];

        if ($this->option('json')) {
            $formats[] = 'json';
        }

        $raw = (string) $this->option('format');
        if ($raw !== '' && $raw !== 'console') {
            $parts = array_map('trim', explode(',', $raw));
            if (in_array('all', $parts, true)) {
                $parts = ['console', 'json', 'html', 'md', 'sarif'];
            }
            foreach ($parts as $part) {
                if ($part !== '' && !in_array($part, $formats, true)) {
                    $formats[] = $part;
                }
            }
        }

        if ($this->option('ci') && !in_array('json', $formats, true)) {
            $formats[] = 'json';
        }

        if (count($formats) === 0) {
            $formats[] = 'console';
        }

        return $formats;
    }

    /**
     * @return list<string>
     */
    private function splitOption(string $name): array
    {
        $value = $this->option($name);
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn ($v): bool => $v !== ''));
    }

    private function resolveOutputDir(string $basePath, string $outputDir): string
    {
        if ($this->isAbsolutePath($outputDir)) {
            return rtrim($outputDir, '/\\');
        }

        return rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . trim($outputDir, '/\\');
    }

    private function isAbsolutePath(string $path): bool
    {
        if (str_starts_with($path, '/') || str_starts_with($path, '\\\\')) {
            return true;
        }

        return preg_match('/^[A-Za-z]:[\\\\\\/]/', $path) === 1;
    }

    /**
     * @param CheckResult[] $results
     * @return list<array<string, mixed>>
     */
    private function resultsToArrays(array $results): array
    {
        return array_map(static fn (CheckResult $result): array => $result->toArray(), $results);
    }

    /**
     * @param list<array<string, mixed>> $data
     * @return CheckResult[]
     */
    private function arraysToResults(array $data): array
    {
        return array_map(static fn (array $item): CheckResult => CheckResult::fromArray($item), $data);
    }
}
