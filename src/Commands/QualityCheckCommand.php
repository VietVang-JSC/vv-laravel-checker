<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Commands;

use Illuminate\Console\Command;
use VietVang\QualityChecker\Baseline\BaselineFilter;
use VietVang\QualityChecker\Baseline\BaselineManager;
use VietVang\QualityChecker\Fixer\PhpcsFixer;
use VietVang\QualityChecker\Reporters\ConsoleReporter;
use VietVang\QualityChecker\Reporters\HtmlReporter;
use VietVang\QualityChecker\Reporters\JsonReporter;
use VietVang\QualityChecker\Reporters\MarkdownReporter;
use VietVang\QualityChecker\Reporters\ReporterInterface;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\CheckRunner;

final class QualityCheckCommand extends Command
{
    protected $signature = 'quality:check
        {--format=console : Comma-separated report formats: console,json,html,md or "all".}
        {--only= : Only run these checkers (comma-separated): phpcs,phpstan,phpunit,composer_audit,trivy,custom.}
        {--exclude= : Skip these checkers (comma-separated).}
        {--path=* : Override scan paths (repeatable).}
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
        {--baseline-file= : Baseline file path (default: baseline.json in project root).}';

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

        $results = $this->applyBaseline($ctx, $results);

        if ($ctx->fix) {
            $this->runFixer($ctx);
        }

        $ctx->exitCode = $runner->shouldFail($results) ? 1 : 0;

        $this->render($results, $ctx);

        return $ctx->exitCode;
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

        $packageVersion = $this->packageVersion();

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
                $parts = ['console', 'json', 'html', 'md'];
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

    private function packageVersion(): string
    {
        $file = __DIR__ . '/../../composer.json';
        if (!is_file($file)) {
            return '0.1.0';
        }

        $data = json_decode((string) file_get_contents($file), true);

        return is_array($data) && isset($data['version']) && is_string($data['version'])
            ? $data['version']
            : '0.1.0';
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
