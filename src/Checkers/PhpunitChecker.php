<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Checkers;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

final class PhpunitChecker extends AbstractProcessChecker
{
    public function name(): string
    {
        return 'phpunit';
    }

    public function description(): string
    {
        return 'PHPUnit — test failures / errors.';
    }

    /**
     * @return array<string, mixed>
     */
    public function config(): array
    {
        return [
            'testsuite' => null,
            'coverageThreshold' => 60,
        ];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        return $this->binary('vendor/bin/phpunit', $ctx) !== null;
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('phpunit', $this->config());
        $binary = $this->binary('vendor/bin/phpunit', $ctx);

        if ($binary === null) {
            return $this->result(
                $this->name(),
                $start,
                'skipped',
                [],
                null,
                'phpunit not found. Install it with: composer require --dev phpunit/phpunit'
            );
        }

        $junitFile = $this->temporaryFile('junit-', '.xml');
        $command = [$binary, '--log-junit', $junitFile];

        $testsuite = $config['testsuite'] ?? null;
        if (is_string($testsuite) && $testsuite !== '') {
            $command[] = '--testsuite';
            $command[] = $testsuite;
        }

        // Collect coverage when a coverage driver is available; keep the run
        // non-fatal if Xdebug/PCOV is missing (coverage stays skipped).
        $cloverFile = $this->temporaryFile('clover-', '.xml');
        $command[] = '--coverage-clover';
        $command[] = $cloverFile;

        [$exitCode, $stdout, $stderr] = $this->runProcess($command, $ctx->basePath, 600.0);

        $issues = $this->parseJunit($junitFile);
        $rawOutput = trim($stdout . "\n" . $stderr);

        $tests = 0;
        $failures = 0;
        $errors = 0;
        $skipped = 0;

        $summaryLine = $this->extractSummary($rawOutput);
        $this->statsFromJunit($junitFile, $tests, $failures, $errors, $skipped);

        $coverage = null;
        if (is_file($cloverFile)) {
            $coverage = $this->parseCloverCoverage($cloverFile);
        }

        $coverageThreshold = (int) ($config['coverageThreshold'] ?? 60);
        if ($coverage !== null) {
            if ($coverage < $coverageThreshold) {
                $issues[] = new Issue(
                    'PHPUNIT_LOW_COVERAGE',
                    sprintf('Line coverage is %.1f%%, below the %d%% threshold.', $coverage, $coverageThreshold),
                    null,
                    null,
                    Severity::Error,
                    'phpunit',
                    ['coverage' => $coverage, 'threshold' => $coverageThreshold]
                );
            }
            $summaryLine .= sprintf(' | Coverage: %.1f%%', $coverage);
        }

        @unlink($junitFile);
        @unlink($cloverFile);

        // "There is nothing to run" is not a crash, and reporting it as one is the
        // first thing a new user sees. PHPUnit prints its usage banner and exits
        // 1 when it has no test directory or configuration to work from, so a
        // project that has not written its first test yet gets an `error` row
        // reading "the tool may have failed to run". Distinguish the two on the
        // banner rather than on the exit code, which is 1 in both cases.
        if ($tests === 0 && !$this->foundNothingToRun($rawOutput)) {
            if ($exitCode === 0) {
                return $this->result(
                    $this->name(),
                    $start,
                    'skipped',
                    [],
                    $rawOutput,
                    'No tests found in the project.'
                );
            }

            return $this->result(
                $this->name(),
                $start,
                'error',
                [],
                $rawOutput,
                sprintf('PHPUnit exited with code %d and ran no tests. The tool may have failed to run (e.g. incompatible PHP version).', $exitCode)
            );
        }

        if ($tests === 0) {
            return $this->result(
                $this->name(),
                $start,
                'skipped',
                [],
                $rawOutput,
                'No test suite found in the project — nothing for PHPUnit to run.'
            );
        }

        $status = count($issues) > 0 ? 'failed' : 'passed';
        $summary = sprintf(
            'PHPUnit: %d test(s), %d failure(s), %d error(s), %d skipped. %s',
            $tests,
            $failures,
            $errors,
            $skipped,
            $summaryLine
        );

        return $this->result($this->name(), $start, $status, $issues, $rawOutput, $summary);
    }

    /**
 * Whether PHPUnit exited because it had nothing to run rather than because it
 * broke.
 *
 * PHPUnit prints its usage banner when there is no test directory or config to
 * execute, and "No tests executed!" when a suite is configured but empty. Both
 * exit non-zero. A genuine crash — a bad PHP version, a broken bootstrap — reads
 * differently: it names the failure and never prints usage.
 */
    private function foundNothingToRun(string $output): bool
    {
        return str_contains($output, 'Usage:')
            || str_contains($output, 'No tests executed');
    }

    /**
     * @return list<Issue>
     */
    private function parseJunit(string $file): array
    {
        $issues = [];
        if (!is_file($file)) {
            return $issues;
        }

        $dom = new \DOMDocument();
        if (!@$dom->load($file)) {
            return $issues;
        }

        foreach ($dom->getElementsByTagName('testcase') as $testcase) {
            $file = $testcase->getAttribute('file') ?: null;
            $class = $testcase->getAttribute('class') ?: null;
            $name = $testcase->getAttribute('name') ?: '(unknown)';

            foreach (['failure', 'error'] as $tag) {
                $nodes = $testcase->getElementsByTagName($tag);
                if ($nodes->length === 0) {
                    continue;
                }

                $node = $nodes->item(0);
                $message = $node->getAttribute('message') ?: ($node->textContent ?: 'test ' . $tag);
                $line = (int) $node->getAttribute('line') ?: null;

                $issues[] = new Issue(
                    strtoupper('PHPUNIT_' . $tag),
                    sprintf('[%s::%s] %s', $class ?? 'test', $name, $message),
                    $file,
                    $line > 0 ? $line : null,
                    Severity::Error,
                    'phpunit',
                    ['class' => $class, 'method' => $name, 'kind' => $tag]
                );
            }
        }

        return $issues;
    }

    private function statsFromJunit(?string $file, int &$tests, int &$failures, int &$errors, int &$skipped): void
    {
        if ($file === null || !is_file($file)) {
            return;
        }

        $dom = new \DOMDocument();
        if (!@$dom->load($file)) {
            return;
        }

        $suites = $dom->getElementsByTagName('testsuite');
        if ($suites->length === 0) {
            return;
        }

        $root = $suites->item(0);
        $tests += (int) $root->getAttribute('tests');
        $failures += (int) $root->getAttribute('failures');
        $errors += (int) $root->getAttribute('errors');
        $skipped += (int) $root->getAttribute('skipped');
    }

    private function parseCloverCoverage(string $file): ?float
    {
        $dom = new \DOMDocument();
        if (!@$dom->load($file)) {
            return null;
        }

        $metrics = $dom->getElementsByTagName('metrics');
        if ($metrics->length === 0) {
            return null;
        }

        $elements = 0;
        $covered = 0;
        foreach ($metrics as $metric) {
            $elements += (int) $metric->getAttribute('statements');
            $covered += (int) $metric->getAttribute('coveredstatements');
        }

        if ($elements <= 0) {
            return null;
        }

        return round(($covered / $elements) * 100, 1);
    }

    private function extractSummary(string $rawOutput): string
    {
        $pattern = '/Tests:\s+\d+(,\s+\S+)*/';
        if (preg_match($pattern, $rawOutput, $m) === 1) {
            return trim($m[0]);
        }

        return '';
    }

    private function temporaryFile(string $prefix, string $suffix): string
    {
        $dir = sys_get_temp_dir();

        return $dir . DIRECTORY_SEPARATOR . $prefix . bin2hex(random_bytes(6)) . $suffix;
    }
}
