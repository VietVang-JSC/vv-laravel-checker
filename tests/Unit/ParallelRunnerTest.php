<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Checkers\CheckerInterface;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\ParallelRunner;

final class ParallelRunnerTest extends TestCase
{
    public function testParallelSupportedReturnsBool(): void
    {
        $runner = new ParallelRunner(2);

        self::assertIsBool($runner->parallelSupported());
        self::assertSame(2, $runner->maxConcurrency());
    }

    public function testRunReturnsResultsIncludingSkippedForUnavailable(): void
    {
        $runner = new ParallelRunner(4);
        $ctx = new CheckContext(sys_get_temp_dir(), ['app'], [], sys_get_temp_dir() . '/reports', noCache: true);

        $available = new class () implements CheckerInterface {
            public function name(): string
            {
                return 'fake_available';
            }

            public function description(): string
            {
                return 'A fake checker that is available.';
            }

            public function isAvailable(CheckContext $ctx): bool
            {
                return true;
            }

            public function run(CheckContext $ctx): CheckResult
            {
                return new CheckResult(
                    $this->name(),
                    'failed',
                    0.1,
                    [new Issue('FAKE', 'fake issue', 'file.php', 1, Severity::Error, 'fake')],
                    null,
                    null
                );
            }

            /**
             * @return array<string, mixed>
             */
            public function config(): array
            {
                return [];
            }
        };

        $unavailable = new class () implements CheckerInterface {
            public function name(): string
            {
                return 'fake_unavailable';
            }

            public function description(): string
            {
                return 'A fake checker that is not available.';
            }

            public function isAvailable(CheckContext $ctx): bool
            {
                return false;
            }

            public function run(CheckContext $ctx): CheckResult
            {
                return new CheckResult($this->name(), 'error', 0.0, [], null, null);
            }

            /**
             * @return array<string, mixed>
             */
            public function config(): array
            {
                return [];
            }
        };

        $results = $runner->run([$available, $unavailable], $ctx);

        self::assertCount(2, $results);

        $names = array_map(static fn (CheckResult $r): string => $r->name, $results);
        self::assertContains('fake_available', $names);
        self::assertContains('fake_unavailable', $names);

        foreach ($results as $result) {
            self::assertInstanceOf(CheckResult::class, $result);
        }

        $skipped = $this->byName($results, 'fake_unavailable');
        self::assertSame('skipped', $skipped->status);
        self::assertSame([], $skipped->issues);

        $ran = $this->byName($results, 'fake_available');
        self::assertSame('failed', $ran->status);
        self::assertCount(1, $ran->issues);
    }

    /**
     * @param CheckResult[] $results
     */
    private function byName(array $results, string $name): CheckResult
    {
        foreach ($results as $result) {
            if ($result->name === $name) {
                return $result;
            }
        }

        self::fail('Result not found for checker: ' . $name);
    }
}
