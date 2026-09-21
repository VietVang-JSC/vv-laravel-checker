<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use Symfony\Component\Process\Process;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class ComposerAuditChecker extends AbstractProcessChecker
{
    public function name(): string
    {
        return 'composer_audit';
    }

    public function description(): string
    {
        return 'Composer audit — known vulnerabilities in dependencies.';
    }

    public function config(): array
    {
        return [
            'enabled' => true,
        ];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        return $this->locateComposer($ctx) !== null;
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('composer_audit', $this->config());

        if (!($config['enabled'] ?? true)) {
            return $this->result($this->name(), $start, 'skipped', [], null, 'Composer audit is disabled in configuration.');
        }

        $composer = $this->locateComposer($ctx);
        if ($composer === null) {
            return $this->result(
                $this->name(),
                $start,
                'skipped',
                [],
                null,
                'composer binary not found. Install Composer to run dependency audits.'
            );
        }

        [$exitCode, $stdout, $stderr] = $this->runProcess([$composer, 'audit', '--format=json', '--no-interaction'], $ctx->basePath, 120.0);

        $issues = $this->parseOutput($stdout);
        $rawOutput = trim($stdout . "\n" . $stderr);

        // composer audit exits 0 even when advisories are found; a non-zero code
        // here means it failed to resolve/lookup (e.g. offline, rate-limited).
        if ($exitCode !== 0 && count($issues) === 0) {
            return $this->result(
                $this->name(),
                $start,
                'error',
                [],
                $rawOutput,
                sprintf('Composer audit exited with code %d (offline or rate-limited?). %s', $exitCode, $this->firstLine($rawOutput))
            );
        }

        $status = count($issues) > 0 ? 'failed' : 'passed';
        $summary = sprintf('Composer audit found %d advisory(ies).', count($issues));

        return $this->result($this->name(), $start, $status, $issues, $rawOutput, $summary);
    }

    private function firstLine(string $text): string
    {
        $text = trim($text);
        if ($text === '') {
            return 'No output.';
        }

        $lines = preg_split('/\r\n|\r|\n/', $text) ?: [];

        return $lines[0];
    }

    private function parseOutput(string $json): array
    {
        $issues = [];
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return $issues;
        }

        foreach (($decoded['advisories'] ?? []) as $package => $advisories) {
            if (!is_array($advisories)) {
                continue;
            }

            foreach ($advisories as $advisory) {
                if (!is_array($advisory)) {
                    continue;
                }

                $title = (string) ($advisory['title'] ?? 'Advisory for ' . $package);
                $severity = (string) ($advisory['severity'] ?? 'medium');
                $issues[] = new Issue(
                    (string) ($advisory['advisoryId'] ?? 'COMPOSER_ADVISORY'),
                    sprintf('%s (%s) — %s', $package, (string) ($advisory['cve'] ?? 'no CVE'), $title),
                    null,
                    null,
                    $this->mapSeverity($severity),
                    'composer_audit',
                    [
                        'package' => $package,
                        'advisory' => $advisory['advisoryId'] ?? null,
                        'link' => $advisory['link'] ?? null,
                        'severity' => $severity,
                    ]
                );
            }
        }

        return $issues;
    }

    private function mapSeverity(string $severity): Severity
    {
        return match (strtolower($severity)) {
            'critical' => Severity::Critical,
            'high' => Severity::Error,
            'medium' => Severity::Warning,
            default => Severity::Info,
        };
    }

    private function locateComposer(CheckContext $ctx): ?string
    {
        foreach ([$ctx->basePath . DIRECTORY_SEPARATOR . 'composer.phar'] as $candidate) {
            if (is_file($candidate)) {
                return PHP_BINARY . ' ' . $candidate;
            }
        }

        $process = new Process([PHP_OS_FAMILY === 'Windows' ? 'where' : 'which', 'composer']);
        $process->run();

        return $process->isSuccessful() ? 'composer' : null;
    }
}
