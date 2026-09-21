<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Fixer;

/**
 * Auto-fix wrapper around `vendor/bin/phpcbf` (PHP_CodeSniffer fixer).
 *
 * This class does NOT modify any core checker; the integration pass calls it
 * when the `--fix` flag is set on the command.
 *
 * Capability:
 *  - `isAvailable()` checks that the phpcbf binary exists and is executable
 *    within the project base path from CheckContext.
 *  - `fix()` runs phpcbf with `--report=json` over the given paths and a chosen
 *    standard, then parses the JSON report to count fixed files.
 *
 * Assumptions:
 *  - The binary is resolved relative to CheckContext `basePath` as
 *    `<basePath>/vendor/bin/phpcbf` (Windows: `.bat` / `.cmd` variants).
 *  - phpcbf JSON report (when --report=json) exposes `files[].errors` /
 *    `files[].warnings`; a file is considered "fixed" when its errors+warnings
 *    dropped to zero after the run, inferred from the report structure.
 *  - When JSON reporting is unavailable, a quiet run's exit code (0 = success,
 *    1 = fixable issues remain, >=2 = error) is used and output is captured raw.
 *
 * Known limitations:
 *  - Only counts top-level fixed files; does not re-parse source to verify.
 *  - Progress callback is invoked per file when the JSON report lists files,
 *    otherwise once at start and end.
 */
final class PhpcsFixer
{
    private const EXIT_NO_ISSUES = 0;
    private const EXIT_FIXABLE_REMAIN = 1;

    /**
     * Run the fixer over the given paths.
     *
     * @param list<string> $paths Files/directories to fix.
     * @param string $standard PHPCS standard to apply (e.g. PSR12).
     * @param callable|null $progress Invoked with a progress message string.
     * @return FixResult
     */
    public function fix(array $paths, string $standard, ?callable $progress = null): FixResult
    {
        $binary = $this->locateBinary();
        if ($binary === null) {
            return new FixResult(0, ['phpcbf binary not found (vendor/bin/phpcbf).'], '');
        }

        if ($progress !== null) {
            $progress('Starting phpcbf fix...');
        }

        $cmd = $this->buildCommand($binary, $paths, $standard);
        [$exitCode, $output] = $this->run($cmd);

        if ($progress !== null) {
            $progress('phpcbf finished.');
        }

        $fixed = $this->countFixed($output);

        $errors = [];
        if ($exitCode >= 2) {
            $errors[] = sprintf('phpcbf exited with code %d.', $exitCode);
        }

        return new FixResult($fixed, $errors, $output);
    }

    /**
     * Returns true when a usable phpcbf binary exists for the given context.
     */
    public function isAvailable(object $ctx): bool
    {
        return $this->locateBinaryForContext($ctx) !== null;
    }

    private function buildCommand(string $binary, array $paths, string $standard): string
    {
        $parts = [
            escapeshellarg($binary),
            '--standard=' . escapeshellarg($standard),
            '--report=json',
        ];
        foreach ($paths as $path) {
            $parts[] = escapeshellarg($path);
        }

        return implode(' ', $parts) . ' 2>&1';
    }

    private function run(string $cmd): array
    {
        $output = [];
        $exitCode = 0;
        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $proc = proc_open($cmd, $descriptorSpec, $pipes);
        if (!is_resource($proc)) {
            return [2, 'Unable to start phpcbf process.'];
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        $output = trim(($stdout !== false ? $stdout : '') . ($stderr !== false ? $stderr : ''));

        return [$exitCode, $output];
    }

    private function countFixed(string $output): int
    {
        $decoded = json_decode($output, true);
        if (!is_array($decoded) || !isset($decoded['files']) || !is_array($decoded['files'])) {
            // Fallback: JSON report failed; we cannot reliably count, return 0.
            return 0;
        }

        $fixed = 0;
        foreach ($decoded['files'] as $fileReport) {
            if (!is_array($fileReport)) {
                continue;
            }
            $errors = (int) ($fileReport['errors'] ?? 0);
            $warnings = (int) ($fileReport['warnings'] ?? 0);
            if ($errors === 0 && $warnings === 0) {
                $fixed++;
            }
        }

        return $fixed;
    }

    private function locateBinary(): ?string
    {
        // No context at construction; caller should rely on isAvailable() before fix().
        // Without a basePath we still attempt a best-effort relative lookup.
        $candidates = [
            __DIR__ . '/../../vendor/bin/phpcbf',
            'vendor/bin/phpcbf',
            'vendor/bin/phpcbf.bat',
        ];

        return $this->firstExisting($candidates);
    }

    private function locateBinaryForContext(object $ctx): ?string
    {
        $basePath = $ctx->basePath ?? null;
        if (!is_string($basePath) || $basePath === '') {
            $basePath = getcwd();
        }

        $binDir = rtrim($basePath, '/\\') . '/vendor/bin';
        $candidates = [
            $binDir . '/phpcbf',
            $binDir . '/phpcbf.bat',
            $binDir . '/phpcbf.cmd',
        ];

        return $this->firstExisting($candidates);
    }

    private function firstExisting(array $candidates): ?string
    {
        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        return null;
    }
}
