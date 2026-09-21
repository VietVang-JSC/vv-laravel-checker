<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Runner;

use VietVang\QualityChecker\Checkers\CheckerInterface;
use VietVang\QualityChecker\Result\CheckResult;

final class ParallelRunner
{
    private int $maxConcurrency;

    public function __construct(int $maxConcurrency = 4)
    {
        $this->maxConcurrency = $maxConcurrency;
    }

    public function maxConcurrency(): int
    {
        return $this->maxConcurrency;
    }

    public function parallelSupported(): bool
    {
        return function_exists('pcntl_fork') || extension_loaded('parallel');
    }

    /**
     * @param CheckerInterface[] $checkers
     * @return CheckResult[]
     */
    public function run(array $checkers, CheckContext $ctx): array
    {
        $executable = array_filter($checkers, static function (CheckerInterface $checker) use ($ctx): bool {
            return $checker->isAvailable($ctx);
        });

        $executable = array_values($executable);

        if ($this->parallelSupported()) {
            $results = $this->runParallel($executable, $ctx);
        } else {
            $results = $this->runSequential($executable, $ctx);
        }

        $skipped = array_values(array_filter($checkers, static function (CheckerInterface $checker) use ($ctx): bool {
            return !$checker->isAvailable($ctx);
        }));

        foreach ($skipped as $checker) {
            $results[] = $this->buildSkipped($checker);
        }

        return $results;
    }

    /**
     * @param CheckerInterface[] $checkers
     * @return CheckResult[]
     */
    private function runParallel(array $checkers, CheckContext $ctx): array
    {
        $results = [];

        if (extension_loaded('parallel') && class_exists('\parallel\Runtime')) {
            $runtime = new \parallel\Runtime();
            $chunks = array_chunk($checkers, max(1, $this->maxConcurrency));

            foreach ($chunks as $chunk) {
                foreach ($chunk as $checker) {
                    $results[] = $checker->run($ctx);
                }
            }

            return $results;
        }

        return $this->runSequential($checkers, $ctx);
    }

    /**
     * @param CheckerInterface[] $checkers
     * @return CheckResult[]
     */
    private function runSequential(array $checkers, CheckContext $ctx): array
    {
        $results = [];
        foreach ($checkers as $checker) {
            $results[] = $checker->run($ctx);
        }

        return $results;
    }

    private function buildSkipped(CheckerInterface $checker): CheckResult
    {
        return new CheckResult(
            $checker->name(),
            'skipped',
            0.0,
            [],
            null,
            sprintf('%s is not available. Install the required tool to enable this checker.', $checker->description())
        );
    }
}
