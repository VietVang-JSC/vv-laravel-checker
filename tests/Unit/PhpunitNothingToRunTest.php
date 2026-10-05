<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\PhpunitChecker;
use ReflectionMethod;

/**
 * "There is nothing to run" is reported as skipped; a real crash is not.
 *
 * PHPUnit exits 1 in both cases, so the exit code alone cannot tell them apart.
 * It prints its usage banner when there is no test directory or configuration
 * to execute, which is what a project that has not written its first test looks
 * like. Before this, that project got an `error` row summarising "the tool may
 * have failed to run (e.g. incompatible PHP version)" — on the very first run,
 * which reads as the tool being broken rather than the project having no tests.
 */
final class PhpunitNothingToRunTest extends TestCase
{
    private function foundNothingToRun(string $output): bool
    {
        $method = new ReflectionMethod(PhpunitChecker::class, 'foundNothingToRun');

        return (bool) $method->invoke(new PhpunitChecker(), $output);
    }

    public function testUsageBannerMeansNothingToRun(): void
    {
        $output = "PHPUnit 11.5.56 by Sebastian Bergmann and contributors.\n\nUsage:\n"
            . "  phpunit [options] <directory|file> ...\n\nConfiguration:\n";

        self::assertTrue($this->foundNothingToRun($output));
    }

    public function testNoTestsExecutedMeansNothingToRun(): void
    {
        self::assertTrue($this->foundNothingToRun("PHPUnit 11.5.56 by Sebastian Bergmann.\nNo tests executed!\n"));
    }

    public function testAFailingSuiteIsNotNothingToRun(): void
    {
        $output = "PHPUnit 11.5.56 by Sebastian Bergmann and contributors.\n\n"
            . "There was 1 failure:\n\n1) ExampleTest::test_a\nFailed asserting that false is true.\n\n"
            . 'FAILURES! Tests: 1, Assertions: 1, Failures: 1.';

        self::assertFalse($this->foundNothingToRun($output));
    }

    public function testAGenuineCrashIsNotNothingToRun(): void
    {
        // What an incompatible PHP version looks like: it names the problem and
        // never prints usage. This must stay an `error`.
        $output = "PHP Fatal error:  Uncaught Error: Class \"Foo\" not found in /app/tests/ExampleTest.php:12\n"
            . "thrown in /app/tests/ExampleTest.php on line 12";

        self::assertFalse($this->foundNothingToRun($output));
    }
}
