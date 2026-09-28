<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Reporters\QualityScore;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

final class QualityScoreTest extends TestCase
{
    private function issue(string $rule, Severity $severity, Confidence $confidence, string $source = 'custom'): Issue
    {
        return new Issue($rule, 'message', 'file.php', 1, $severity, $source, [], $confidence);
    }

    /**
     * @param Issue[] $issues
     * @return list<CheckResult>
     */
    private function results(array $issues): array
    {
        return [new CheckResult('custom', 'failed', 0.1, $issues, null, null)];
    }

    public function testCleanProjectScoresHundredAndPasses(): void
    {
        $score = QualityScore::score($this->results([]));

        self::assertSame(100, $score['overall']);
        self::assertSame('PASS', $score['gate']);
        self::assertSame(0, $score['must_fix']);
    }

    public function testCriticalBlocksGate(): void
    {
        $score = QualityScore::score($this->results([
            $this->issue('HARDCODED_SECRET', Severity::Critical, Confidence::High),
        ]));

        self::assertSame('BLOCKED', $score['gate']);
        self::assertSame(1, $score['must_fix']);
        self::assertSame(90, $score['dimensions']['Security']['score']);
    }

    public function testLowConfidenceNoiseBarelyMovesScore(): void
    {
        $issues = [];
        for ($i = 0; $i < 170; ++$i) {
            $issues[] = $this->issue('MISSING_CONTROLLER_TEST', Severity::Warning, Confidence::Low);
        }
        $score = QualityScore::score($this->results($issues));

        // 170 x 2.0 x 0.25 = 85 deduction, capped per dimension at 100.
        self::assertSame('PASS', $score['gate']);
        self::assertGreaterThanOrEqual(0, $score['dimensions']['Testability']['score']);
        self::assertGreaterThan(50, $score['overall']);
    }

    public function testMediumBladeEchoesDoNotBlock(): void
    {
        $issues = [];
        for ($i = 0; $i < 137; ++$i) {
            $issues[] = $this->issue('OWASP_BLADE_XSS', Severity::Warning, Confidence::Medium);
        }
        $score = QualityScore::score($this->results($issues));

        self::assertSame('PASS', $score['gate']);
        self::assertSame(0, $score['must_fix']);
        self::assertSame(137, $score['review']);
    }

    public function testHighConfidenceSecurityErrorBlocks(): void
    {
        $score = QualityScore::score($this->results([
            $this->issue('OWASP_SSRF', Severity::Error, Confidence::High),
        ]));

        self::assertSame('BLOCKED', $score['gate']);
        self::assertSame(1, $score['must_fix']);
    }

    public function testMediumErrorIsReviewNotMustFix(): void
    {
        $score = QualityScore::score($this->results([
            $this->issue('OWASP_SSRF', Severity::Error, Confidence::Medium),
        ]));

        self::assertSame('PASS', $score['gate']);
        self::assertSame(1, $score['review']);
    }

    public function testDimensionsAndBuckets(): void
    {
        $score = QualityScore::score($this->results([
            $this->issue('MIGRATION_MISSING_DOWN', Severity::Warning, Confidence::Medium),
            $this->issue('ROUTE_MISSING_VALIDATION', Severity::Warning, Confidence::Medium),
        ]));

        self::assertArrayHasKey('Database', $score['dimensions']);
        self::assertArrayHasKey('Reliability', $score['dimensions']);
        self::assertSame(2, $score['tech_debt']);
        self::assertSame(99, $score['dimensions']['Database']['score']);
    }

    public function testTopMustFixListsRules(): void
    {
        $score = QualityScore::score($this->results([
            $this->issue('HARDCODED_SECRET', Severity::Critical, Confidence::High),
            $this->issue('HARDCODED_SECRET', Severity::Critical, Confidence::High),
            $this->issue('UNSAFE_EVAL', Severity::Critical, Confidence::High),
        ]));

        self::assertSame('HARDCODED_SECRET', $score['top_must_fix'][0]['rule']);
        self::assertSame(2, $score['top_must_fix'][0]['count']);
    }
}
