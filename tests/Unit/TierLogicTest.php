<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Runner\CheckRunner;

final class TierLogicTest extends TestCase
{
    private function issue(Severity $severity, Confidence $confidence, string $source = 'custom'): Issue
    {
        return new Issue('R', 'm', 'f.php', 1, $severity, $source, [], $confidence);
    }

    private function context(string $tier, string $minConf = 'low', string $failOn = 'error'): CheckContext
    {
        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            sys_get_temp_dir() . '/r',
            tier: $tier,
            minConfidence: $minConf,
            failOn: $failOn,
        );
    }

    public function testSecurityTierIgnoresLowConfidenceIssue(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Critical, Confidence::Low),
        ], null, null);

        self::assertFalse($runner->shouldFail([$result]));
    }

    public function testSecurityTierFailsOnHighConfidenceSecurityIssue(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::High),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }

    public function testQualityTierFailsOnMediumConfidenceError(): void
    {
        $runner = new CheckRunner($this->context('quality'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::Medium),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }

    public function testMinConfidenceHighFiltersMedium(): void
    {
        $runner = new CheckRunner($this->context('quality', 'high'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Critical, Confidence::Medium),
        ], null, null);

        self::assertFalse($runner->shouldFail([$result]));
    }

    public function testSecurityTierAlwaysCountsComposerAudit(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('composer_audit', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::Medium, 'composer_audit'),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }
}
