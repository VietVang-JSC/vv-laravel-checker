<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

final class IssueRoundTripTest extends TestCase
{
    public function testIssueRoundTrip(): void
    {
        $issue = new Issue(
            'SQL_INJECTION',
            'taint',
            '/app/Http/Controllers/UserController.php',
            42,
            Severity::Critical,
            'custom',
            ['method' => 'select']
        );

        $array = $issue->toArray();
        $restored = Issue::fromArray($array);

        self::assertSame($issue->rule, $restored->rule);
        self::assertSame($issue->message, $restored->message);
        self::assertSame($issue->file, $restored->file);
        self::assertSame($issue->line, $restored->line);
        self::assertSame($issue->severity, $restored->severity);
        self::assertSame($issue->metadata, $restored->metadata);
    }

    public function testConfidenceScoreMapping(): void
    {
        $high = new Issue('R', 'm', 'f.php', 1, Severity::Error, 'custom', [], Confidence::High);
        $medium = new Issue('R', 'm', 'f.php', 1, Severity::Error, 'custom', [], Confidence::Medium);
        $low = new Issue('R', 'm', 'f.php', 1, Severity::Error, 'custom', [], Confidence::Low);

        self::assertSame(1.0, $high->confidenceScore());
        self::assertSame(0.5, $medium->confidenceScore());
        self::assertSame(0.25, $low->confidenceScore());
        self::assertSame(0.5, $medium->toArray()['confidence_score']);
    }

    public function testCheckResultRoundTrip(): void
    {
        $result = new CheckResult(
            'custom',
            'failed',
            1.25,
            [new Issue('A', 'b', 'c.php', 1, Severity::Warning, 'custom')],
            'raw',
            'summary'
        );

        $restored = CheckResult::fromArray($result->toArray());

        self::assertSame($result->name, $restored->name);
        self::assertSame($result->status, $restored->status);
        self::assertSame(count($result->issues), count($restored->issues));
        self::assertSame($result->issues[0]->severity, $restored->issues[0]->severity);
    }

    public function testContextDefaults(): void
    {
        $ctx = new CheckContext('/base', ['app'], [], '/base/reports', noCache: true);

        self::assertTrue($ctx->noCache);
        self::assertFalse($ctx->ci);
        self::assertSame('error', $ctx->failOn);
        self::assertSame('/base' . DIRECTORY_SEPARATOR . 'app', $ctx->resolvePath('app'));
    }
}
