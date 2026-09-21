<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

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
