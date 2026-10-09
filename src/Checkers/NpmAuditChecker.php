<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Checkers;

use Symfony\Component\Process\Process;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

final class NpmAuditChecker extends AbstractProcessChecker
{
    public function name(): string
    {
        return 'npm_audit';
    }

    public function description(): string
    {
        return 'npm audit — known vulnerabilities in npm dependencies.';
    }

    /**
     * @return array<string, mixed>
     */
    public function config(): array
    {
        return ['enabled' => true];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        return $this->hasPackageJson($ctx) && $this->npmBinary() !== null;
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('npm_audit', $this->config());
        if (!($config['enabled'] ?? true)) {
            return $this->result($this->name(), $start, 'skipped', [], null, 'npm audit is disabled in configuration.');
        }
        if (!$this->hasPackageJson($ctx)) {
            return $this->result($this->name(), $start, 'skipped', [], null, 'No package.json found — skipping npm audit.');
        }
        $npm = $this->npmBinary();
        if ($npm === null) {
            return $this->result($this->name(), $start, 'skipped', [], null, 'npm binary not found. Install Node.js to run npm audit.');
        }

        [$exitCode, $stdout, $stderr] = $this->runProcess([$npm, 'audit', '--json'], $ctx->basePath, 120.0);
        $issues = $this->parseOutput($stdout);
        $rawOutput = trim($stdout . "\n" . $stderr);

        if ($exitCode !== 0 && count($issues) === 0 && str_contains($rawOutput, 'ENOTFOUND')) {
            return $this->result($this->name(), $start, 'error', [], $rawOutput, 'npm audit failed (offline or registry unreachable).');
        }

        $status = count($issues) > 0 ? 'failed' : 'passed';
        $summary = sprintf('npm audit found %d advisory(ies).', count($issues));

        return $this->result($this->name(), $start, $status, $issues, $rawOutput, $summary);
    }

    private function hasPackageJson(CheckContext $ctx): bool
    {
        return is_file($ctx->basePath . DIRECTORY_SEPARATOR . 'package.json');
    }

    private function npmBinary(): ?string
    {
        $which = PHP_OS_FAMILY === 'Windows' ? 'where' : 'which';
        $process = new Process([$which, 'npm']);
        $process->run();

        return $process->isSuccessful() ? 'npm' : null;
    }

    /**
     * @return list<Issue>
     */
    private function parseOutput(string $json): array
    {
        $issues = [];
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return $issues;
        }
        $vulns = $decoded['vulnerabilities'] ?? $decoded['advisories'] ?? [];
        if (!is_array($vulns)) {
            return $issues;
        }
        foreach ($vulns as $pkg => $data) {
            if (!is_array($data)) {
                continue;
            }
            // npm v7+ shape: vulnerabilities: { pkg: { via: [...], severity, range } }
            $severity = (string) ($data['severity'] ?? 'moderate');
            $title = is_string($data['title'] ?? null) ? $data['title'] : sprintf('Vulnerability in %s', $pkg);
            $issues[] = new Issue(
                'NPM_AUDIT',
                sprintf('%s — %s', $pkg, $title),
                null,
                null,
                $this->mapSeverity($severity),
                'npm_audit',
                ['package' => $pkg, 'severity' => $severity]
            );
        }

        return $issues;
    }

    private function mapSeverity(string $severity): Severity
    {
        return match (strtolower($severity)) {
            'critical' => Severity::Critical,
            'high' => Severity::Error,
            'moderate', 'medium' => Severity::Warning,
            default => Severity::Info,
        };
    }
}
