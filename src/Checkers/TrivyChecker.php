<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use Symfony\Component\Process\Process;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class TrivyChecker implements CheckerInterface
{
    public function name(): string
    {
        return 'trivy';
    }

    public function description(): string
    {
        return 'Scans the filesystem / infrastructure-as-code config for vulnerabilities, misconfigurations and secrets using Trivy.';
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        $config = $ctx->configFor('trivy', $this->config());
        if (!($config['enabled'] ?? false)) {
            return false;
        }

        $binary = $config['binary'] ?? 'trivy';

        return $this->binaryExists($binary) || $this->cachedBinary($ctx) !== null;
    }

    public function config(): array
    {
        return ['enabled' => false, 'mode' => 'config', 'binary' => 'trivy', 'version' => null];
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('trivy', $this->config());

        if (!($config['enabled'] ?? false)) {
            return $this->result($start, 'skipped', [], null, 'Trivy is disabled in configuration.');
        }

        $binary = $config['binary'] ?? 'trivy';

        if (!$this->binaryExists($binary)) {
            $cached = $this->cachedBinary($ctx);
            if ($cached !== null) {
                $binary = $cached;
            } else {
                return $this->result(
                    $start,
                    'skipped',
                    [],
                    null,
                    'Trivy binary not found. Install it from https://aquasecurity.github.io/trivy/ or run with auto-install enabled.'
                );
            }
        }

        $mode = $config['mode'] ?? 'config';
        $basePath = $ctx->basePath ?? $ctx->paths[0] ?? getcwd() ?: getcwd();

        $command = [$binary];
        if ($mode === 'fs') {
            $command[] = 'fs';
        } else {
            $command[] = 'config';
        }
        $command[] = '--format';
        $command[] = 'json';
        $command[] = $basePath;

        $process = new Process($command);
        $process->setTimeout(null);
        $process->run();

        $rawOutput = $process->getOutput();
        $exitCode = $process->getExitCode();

        $issues = $this->parseOutput($rawOutput);

        if ($exitCode !== 0 && count($issues) === 0) {
            return $this->result(
                $start,
                'error',
                [],
                $rawOutput,
                'Trivy failed with exit code ' . $exitCode . '. Check the raw output for details.'
            );
        }

        $status = count($issues) === 0 ? 'passed' : 'warning';
        $summary = sprintf(
            'Trivy %s scan found %d issue(s) in %s.',
            $mode,
            count($issues),
            $basePath
        );

        return $this->result($start, $status, $issues, $rawOutput, $summary);
    }

    private function parseOutput(string $rawOutput): array
    {
        $issues = [];
        $decoded = json_decode($rawOutput, true);

        if (!is_array($decoded)) {
            return $issues;
        }

        $results = $decoded['Results'] ?? [];
        if (!is_array($results)) {
            return $issues;
        }

        foreach ($results as $result) {
            if (!is_array($result)) {
                continue;
            }

            $target = (string) ($result['Target'] ?? '(unknown)');

            foreach (($result['Misconfigurations'] ?? []) as $misconfig) {
                if (!is_array($misconfig)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    (string) ($misconfig['AVDID'] ?? $misconfig['ID'] ?? 'TRIVY_MISCONFIG'),
                    (string) ($misconfig['Title'] ?? $misconfig['Message'] ?? 'Misconfiguration detected'),
                    $target,
                    (int) ($misconfig['CauseMetadata']['StartLine'] ?? 0),
                    $this->mapSeverity((string) ($misconfig['Severity'] ?? 'UNKNOWN')),
                    ['type' => 'misconfig', 'severity' => $misconfig['Severity'] ?? 'UNKNOWN']
                );
            }

            foreach (($result['Secrets'] ?? []) as $secret) {
                if (!is_array($secret)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    (string) ($secret['RuleID'] ?? 'TRIVY_SECRET'),
                    (string) ($secret['Title'] ?? 'Sensitive information found'),
                    $target,
                    (int) ($secret['StartLine'] ?? 0),
                    $this->mapSeverity((string) ($secret['Severity'] ?? 'UNKNOWN')),
                    ['type' => 'secret', 'severity' => $secret['Severity'] ?? 'UNKNOWN']
                );
            }
        }

        return $issues;
    }

    private function makeIssue(string $rule, string $message, string $file, int $line, Severity $severity, array $metadata): Issue
    {
        return new Issue(
            $rule,
            $message,
            $file,
            $line > 0 ? $line : null,
            $severity,
            'trivy',
            $metadata
        );
    }

    private function mapSeverity(string $severity): Severity
    {
        $upper = strtoupper($severity);

        return match ($upper) {
            'CRITICAL' => Severity::Critical,
            'HIGH' => Severity::Error,
            'MEDIUM' => Severity::Warning,
            default => Severity::Info,
        };
    }

    private function binaryExists(string $binary): bool
    {
        $which = PHP_OS_FAMILY === 'Windows' ? 'where' : 'which';
        $process = new Process([$which, $binary]);
        $process->run();

        return $process->isSuccessful();
    }

    private function cachedBinary(CheckContext $ctx): ?string
    {
        if (class_exists(\VietVang\QualityChecker\Tools\TrivyDownloader::class)) {
            $downloader = new \VietVang\QualityChecker\Tools\TrivyDownloader($ctx);

            return $downloader->binaryPath();
        }

        return null;
    }

    private function result(
        float $start,
        string $status,
        array $issues,
        ?string $rawOutput,
        ?string $summary
    ): CheckResult {
        return new CheckResult(
            $this->name(),
            $status,
            microtime(true) - $start,
            $issues,
            $rawOutput,
            $summary
        );
    }
}
