<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\CheckRunner;

final class CheckRunnerTest extends TestCase
{
    private function context(string $failOn): CheckContext
    {
        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            sys_get_temp_dir() . '/reports',
            failOn: $failOn,
        );
    }

    private function resultWithIssue(Severity $severity): CheckResult
    {
        $issue = new Issue('RULE_X', 'message', 'file.php', 1, $severity, 'custom');

        return new CheckResult('custom', 'failed', 0.1, [$issue], null, null);
    }

    public function testShouldFailOnErrorByDefault(): void
    {
        $runner = new CheckRunner($this->context('error'));

        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Error)]));
        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Warning)]));
        self::assertFalse($runner->shouldFail([new CheckResult('phpcs', 'passed', 0.1, [], null, null)]));
    }

    public function testShouldFailOnWarning(): void
    {
        $runner = new CheckRunner($this->context('warning'));

        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Warning)]));
    }

    public function testShouldFailOnCritical(): void
    {
        $runner = new CheckRunner($this->context('critical'));

        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Error)]));
        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Critical)]));
    }

    public function testShouldNeverFailOnNone(): void
    {
        $runner = new CheckRunner($this->context('none'));

        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Critical)]));
    }
}
