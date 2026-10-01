<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Standalone;

use Rampart\QualityChecker\Baseline\BaselineFilter;
use Rampart\QualityChecker\Baseline\BaselineManager;
use Rampart\QualityChecker\Baseline\IssueDelta;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Reporters\ConsoleReporter;
use Rampart\QualityChecker\Reporters\HtmlReporter;
use Rampart\QualityChecker\Reporters\JsonReporter;
use Rampart\QualityChecker\Reporters\MarkdownReporter;
use Rampart\QualityChecker\Reporters\ReporterInterface;
use Rampart\QualityChecker\Reporters\SarifReporter;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Runner\CheckRunner;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Standalone scan entry: same engine as `php artisan quality:check`
 * but runnable against any directory without installing the package
 * into the target project (no target vendor, no artisan needed).
 *
 * Only checkers that work from static sources run here; anything
 * needing the target runtime (target phpunit run) is skipped unless
 * explicitly requested via --only.
 */
final class StandaloneRunner
{
    /** @var array<string, string> */
    private array $options = [];

    /** @var list<string> */
    private array $paths = [];

    private string $target = '';

    /**
     * @param list<string> $argv argv without the script name
     */
    public function __construct(array $argv)
    {
        $this->parseArgv($argv);
    }

    public function run(OutputInterface $output, string $toolRoot): int
    {
        if (isset($this->options['help']) || $this->target === '') {
            $this->printHelp($output);

            return $this->target === '' && !isset($this->options['help']) ? 2 : 0;
        }
        $target = $this->target;
        if (!is_dir($target)) {
            $output->writeln('<error>Target directory not found: ' . $target . '</error>');

            return 2;
        }

        $config = $this->loadConfig($toolRoot);
        $ctx = new CheckContext(
            $target,
            $this->scanPaths($target),
            $config,
            $this->outputDir($target),
            noAutoInstall: true,
            failOn: $this->options['fail-on'] ?? 'error',
            tier: $this->options['tier'] ?? ($config['tier'] ?? 'quality'),
            minConfidence: $this->options['min-confidence'] ?? 'low',
        );
        $ctx->only = $this->split($this->options['only'] ?? 'custom');
        $ctx->exclude = $this->split($this->options['exclude'] ?? '');
        $ctx->noCache = isset($this->options['no-cache']);
        $ctx->profile = isset($this->options['profile']);
        $ctx->exitCode = 0;
        $ctx->baselineFile = $this->options['baseline-file'] ?? ($target . DIRECTORY_SEPARATOR . 'baseline.json');
        $ctx->metadata = ['format' => $this->formats()];

        $runner = new CheckRunner($ctx);
        $results = $runner->run($runner->buildCheckers());
        $results = $this->applyBaseline($ctx, $results, $output);

        $ctx->exitCode = $runner->shouldFail($results) ? 1 : 0;

        foreach ($this->formats() as $format) {
            $reporter = $this->reporterFor($format, $output);
            if ($reporter !== null) {
                $reporter->render($results, $ctx);
            }
        }
        if ($ctx->profile) {
            file_put_contents(
                rtrim($ctx->outputDir, '/\\') . DIRECTORY_SEPARATOR . 'profile.json',
                json_encode(Profiler::report(), JSON_PRETTY_PRINT)
            );
        }

        $total = 0;
        foreach ($results as $result) {
            $total += count($result->issues);
        }
        $output->writeln(sprintf('Standalone scan: %d issue(s) in %s (exit %d).', $total, $ctx->outputDir, $ctx->exitCode));

        return $ctx->exitCode;
    }

    /**
     * @param list<string> $argv
     */
    private function parseArgv(array $argv): void
    {
        foreach ($argv as $arg) {
            if (!str_starts_with($arg, '--')) {
                if ($this->target === '') {
                    $this->target = rtrim($arg, '/\\');
                }
                continue;
            }
            $pair = explode('=', substr($arg, 2), 2);
            $key = $pair[0];
            $value = $pair[1] ?? '1';
            if ($key === 'path') {
                $this->paths[] = $value;
                continue;
            }
            $this->options[$key] = $value;
        }
    }

    /**
     * @return list<string>
     */
    private function formats(): array
    {
        $raw = $this->options['format'] ?? 'console';
        $parts = array_values(array_filter(array_map('trim', explode(',', $raw))));
        if (in_array('all', $parts, true)) {
            return ['console', 'json', 'html', 'md', 'sarif'];
        }

        return $parts === [] ? ['console'] : $parts;
    }

    /**
     * @return list<string>
     */
    private function split(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value))));
    }

    /**
     * @return list<string>
     */
    private function scanPaths(string $target): array
    {
        if ($this->paths !== []) {
            return $this->paths;
        }

        return array_values(array_filter(
            ['app', 'src', 'routes', 'config', 'database', 'tests', 'resources', 'packages'],
            static fn (string $p): bool => is_dir($target . DIRECTORY_SEPARATOR . $p)
        ));
    }

    private function outputDir(string $target): string
    {
        $out = $this->options['output'] ?? 'reports/quality-checker';
        if (preg_match('/^[A-Za-z]:[\\\\\\/]/', $out) === 1 || str_starts_with($out, '/')) {
            return rtrim($out, '/\\');
        }

        return rtrim($target, '/\\') . DIRECTORY_SEPARATOR . trim($out, '/\\');
    }

    /**
     * @return array<string, mixed>
     */
    private function loadConfig(string $toolRoot): array
    {
        $file = rtrim($toolRoot, '/\\') . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'quality-checker.php';
        if (!is_file($file)) {
            return [];
        }
        $config = require $file;

        return is_array($config) ? $config : [];
    }

    /**
     * @param CheckResult[] $results
     * @return CheckResult[]
     */
    private function applyBaseline(CheckContext $ctx, array $results, OutputInterface $output): array
    {
        $generate = isset($this->options['baseline-generate']);
        $update = isset($this->options['baseline-update']);
        if (!$generate && !$update && !is_file($ctx->baselineFile)) {
            return $results;
        }
        $manager = new BaselineManager($ctx->baselineFile);
        $arrays = array_map(static fn (CheckResult $r): array => $r->toArray(), $results);
        if ($generate || $update) {
            $manager->update($arrays, $ctx->baselineFile);
            $output->writeln('Baseline written to ' . $ctx->baselineFile . '.');

            return $results;
        }
        $manager->load();
        $filter = new BaselineFilter($manager);
        $filtered = $filter->filter($arrays);
        $delta = IssueDelta::compute($filtered, $manager->signatures());
        $ctx->metadata['delta'] = [
            'new' => count($delta['new']),
            'fixed' => $delta['fixed'],
            'existing' => $delta['existing'],
            'new_by_rule' => $delta['new_by_rule'],
        ];

        return array_map(static fn (array $item): CheckResult => CheckResult::fromArray($item), $filtered);
    }

    private function reporterFor(string $format, OutputInterface $output): ?ReporterInterface
    {
        return match ($format) {
            'console' => new ConsoleReporter($output),
            'json' => new JsonReporter(),
            'html' => new HtmlReporter(),
            'md' => new MarkdownReporter(),
            'sarif' => new SarifReporter(),
            default => null,
        };
    }

    private function printHelp(OutputInterface $output): void
    {
        $output->writeln('Usage: php bin/quality-check <target-dir> [options]');
        $output->writeln('  --format=console|json|html|md|sarif|all (default: console)');
        $output->writeln('  --tier=security|quality|all  --only=custom,...  --exclude=...');
        $output->writeln('  --fail-on=none|info|warning|error|critical  --min-confidence=low|medium|high');
        $output->writeln('  --output=<dir>  --path=<sub> (repeatable)  --no-cache  --profile');
        $output->writeln('  --baseline-file=<file>  --baseline-generate  --baseline-update  --help');
        $output->writeln('Default --only=custom: static analyzers only, no target vendor needed.');
    }
}
