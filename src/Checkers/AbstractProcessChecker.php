<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use Symfony\Component\Process\Process;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Runner\CheckContext;

abstract class AbstractProcessChecker implements CheckerInterface
{
    /**
     * Locate a binary relative to the project base path (e.g. "vendor/bin/phpcs").
     * Returns the first existing candidate (with .bat/.cmd fallbacks on Windows).
     */
    protected function binary(string $relative, CheckContext $ctx): ?string
    {
        $binDir = $ctx->basePath . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin';
        $name = basename($relative);
        $candidates = [
            $binDir . DIRECTORY_SEPARATOR . $name,
            $binDir . DIRECTORY_SEPARATOR . $name . '.bat',
            $binDir . DIRECTORY_SEPARATOR . $name . '.cmd',
            $ctx->basePath . DIRECTORY_SEPARATOR . $relative,
        ];

        // Fall back to the package's own vendor/bin (the package may ship/require
        // these tools), so the gate works even when the target project lacks them.
        $packageBin = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin';
        $candidates[] = $packageBin . DIRECTORY_SEPARATOR . $name;
        $candidates[] = $packageBin . DIRECTORY_SEPARATOR . $name . '.bat';
        $candidates[] = $packageBin . DIRECTORY_SEPARATOR . $name . '.cmd';

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Run a process and return [exitCode, stdout, stderr].
     *
     * @param list<string> $command
     * @return array{0: int, 1: string, 2: string}
     */
    protected function runProcess(array $command, ?string $cwd = null, float $timeout = 300.0): array
    {
        $process = new Process($command);
        if ($cwd !== null) {
            $process->setWorkingDirectory($cwd);
        }
        $process->setTimeout($timeout);
        $process->run();

        return [
            $process->getExitCode() ?? -1,
            $process->getOutput(),
            $process->getErrorOutput(),
        ];
    }

    protected function result(
        string $name,
        float $start,
        string $status,
        array $issues,
        ?string $rawOutput,
        ?string $summary,
    ): CheckResult {
        return new CheckResult($name, $status, microtime(true) - $start, $issues, $rawOutput, $summary);
    }
}
