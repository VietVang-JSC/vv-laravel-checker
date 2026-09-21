<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class PhpstanChecker extends AbstractProcessChecker
{
    public function name(): string
    {
        return 'phpstan';
    }

    public function description(): string
    {
        return 'PHPStan — static analysis / type errors.';
    }

    public function config(): array
    {
        return [
            'level' => 5,
            'memoryLimit' => '1G',
        ];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        return $this->binary('vendor/bin/phpstan', $ctx) !== null;
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('phpstan', $this->config());
        $binary = $this->binary('vendor/bin/phpstan', $ctx);

        if ($binary === null) {
            return $this->result(
                $this->name(),
                $start,
                'skipped',
                [],
                null,
                'phpstan not found. Install it with: composer require --dev phpstan/phpstan'
            );
        }

        $level = (int) ($config['level'] ?? 5);
        $memory = (string) ($config['memoryLimit'] ?? '1G');

        $command = [$binary, 'analyse'];

        if (!$this->hasProjectConfig($ctx)) {
            $command[] = '--level=' . $level;
        }

        $command = array_merge(
            $command,
            ['--error-format=json', '--no-progress', '--memory-limit=' . $memory],
            $ctx->paths
        );

        [$exitCode, $stdout, $stderr] = $this->runProcess($command, $ctx->basePath, 600.0);

        $issues = $this->parseOutput($stdout);
        $rawOutput = trim($stdout . "\n" . $stderr);

        if ($exitCode !== 0 && count($issues) === 0) {
            $summary = sprintf(
                'PHPStan exited with code %d and produced no report. The tool may have failed to run (e.g. incompatible PHP version).',
                $exitCode
            );

            return $this->result($this->name(), $start, 'error', [], $rawOutput, $summary);
        }

        $status = count($issues) > 0 ? 'failed' : 'passed';
        $summary = sprintf('PHPStan (level %d) found %d error(s).', $level, count($issues));

        return $this->result($this->name(), $start, $status, $issues, $rawOutput, $summary);
    }

    private function hasProjectConfig(CheckContext $ctx): bool
    {
        foreach (['phpstan.neon', 'phpstan.neon.dist'] as $file) {
            if (is_file($ctx->basePath . DIRECTORY_SEPARATOR . $file)) {
                return true;
            }
        }

        return false;
    }

    private function parseOutput(string $json): array
    {
        $issues = [];
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return $issues;
        }

        foreach (($decoded['files'] ?? []) as $file => $report) {
            if (!is_array($report)) {
                continue;
            }

            foreach (($report['messages'] ?? []) as $message) {
                if (!is_array($message)) {
                    continue;
                }

                $issues[] = new Issue(
                    (string) ($message['identifier'] ?? 'PHPSTAN'),
                    (string) ($message['message'] ?? ''),
                    $file,
                    isset($message['line']) && $message['line'] !== null ? (int) $message['line'] : null,
                    Severity::Error,
                    'phpstan',
                    ['ignorable' => (bool) ($message['ignorable'] ?? false)]
                );
            }
        }

        foreach (($decoded['errors'] ?? []) as $error) {
            if (!is_string($error) || $error === '') {
                continue;
            }

            $issues[] = new Issue('PHPSTAN_ERROR', $error, null, null, Severity::Error, 'phpstan', []);
        }

        return $issues;
    }
}
