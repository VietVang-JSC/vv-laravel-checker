<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Deduplicator;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class ConfidenceDedupTest extends TestCase
{
    public function testConfidenceOrdering(): void
    {
        self::assertLessThan(Confidence::High->intValue(), Confidence::Medium->intValue());
        self::assertLessThan(Confidence::Medium->intValue(), Confidence::Low->intValue());
        self::assertSame('high', Confidence::High->value);
        self::assertSame(Confidence::Low, Confidence::fromString('unknown'));
    }

    public function testIssueDefaultsToHighConfidence(): void
    {
        $issue = new Issue('SQL_INJECTION', 'm', 'f.php', 1, Severity::Critical, 'custom');

        self::assertSame(Confidence::High, $issue->confidence);
        self::assertSame('high', $issue->toArray()['confidence']);
    }

    public function testIssueRoundTripPreservesConfidence(): void
    {
        $issue = new Issue('OWASP_SSRF', 'm', 'f.php', 1, Severity::Error, 'custom', [], Confidence::Medium);
        $restored = Issue::fromArray($issue->toArray());

        self::assertSame(Confidence::Medium, $restored->confidence);
    }

    public function testDeduplicatorKeepsHighestConfidence(): void
    {
        $low = new Issue('RULE', 'same', 'f.php', 1, Severity::Error, 'a', [], Confidence::Low);
        $high = new Issue('RULE', 'same', 'f.php', 1, Severity::Error, 'b', [], Confidence::High);

        $dedup = new Deduplicator();
        $result = new CheckResult('custom', 'failed', 0.1, [$low, $high], null, null);
        $dedup->dedupe([$result]);

        self::assertCount(1, $result->issues);
        self::assertSame(Confidence::High, $result->issues[0]->confidence);
        self::assertSame('b', $result->issues[0]->source);
    }

    public function testDeduplicatorKeepsDistinctIssues(): void
    {
        $a = new Issue('RULE_A', 'm1', 'f.php', 1, Severity::Error, 'a');
        $b = new Issue('RULE_B', 'm2', 'f.php', 2, Severity::Warning, 'b');

        $dedup = new Deduplicator();
        $result = new CheckResult('custom', 'failed', 0.1, [$a, $b], null, null);
        $dedup->dedupe([$result]);

        self::assertCount(2, $result->issues);
    }

    public function testSignatureIncludesFileLineAndMessage(): void
    {
        $issue = new Issue('RULE', 'hello', 'f.php', 5, Severity::Error, 'a');
        $same = new Issue('RULE', 'hello', 'f.php', 5, Severity::Error, 'b');
        $different = new Issue('RULE', 'hello', 'f.php', 6, Severity::Error, 'a');

        self::assertSame($issue->signature(), $same->signature());
        self::assertNotSame($issue->signature(), $different->signature());
    }
}
