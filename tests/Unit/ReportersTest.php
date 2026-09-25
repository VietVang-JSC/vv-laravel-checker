<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use VietVang\QualityChecker\Reporters\ConsoleReporter;
use VietVang\QualityChecker\Reporters\JsonReporter;
use VietVang\QualityChecker\Reporters\MarkdownReporter;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class ReportersTest extends TestCase
{
    private string $tempDir = '';

    protected function tearDown(): void
    {
        if ($this->tempDir !== '' && is_dir($this->tempDir)) {
            foreach (glob($this->tempDir . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
                @unlink((string) $file);
            }
            @rmdir($this->tempDir);
        }
        $this->tempDir = '';
    }

    /**
     * @return CheckResult[]
     */
    private function sampleResults(): array
    {
        return [
            new CheckResult('custom', 'failed', 0.5, [
                new Issue(
                    'SQL_INJECTION',
                    'Tainted input flows into select().',
                    'app/Http/Controllers/UserController.php',
                    14,
                    Severity::Critical,
                    'custom',
                    [],
                    Confidence::High
                ),
                new Issue(
                    'TODO_FIXME',
                    'Leftover TODO marker.',
                    'app/Services/OrderService.php',
                    3,
                    Severity::Info,
                    'custom',
                    [],
                    Confidence::Low
                ),
            ], null, '2 issues'),
            new CheckResult('phpcs', 'passed', 1.25, [], null, null),
        ];
    }

    private function context(): CheckContext
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-rep-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            $this->tempDir,
            packageVersion: '1.0.0'
        );
    }

    /** JsonReporter */

    public function testJsonKeepsStableKeysAndAddsEnterpriseKeys(): void
    {
        $ctx = $this->context();
        $ctx->exitCode = 1;

        (new JsonReporter())->render($this->sampleResults(), $ctx);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        self::assertFileExists($file);

        $payload = json_decode((string) file_get_contents($file), true);
        self::assertIsArray($payload);

        // Stable keys required by SPEC §7.3 (backward compatible).
        foreach (['generated_at', 'package_version', 'exit_code', 'summary', 'checkers'] as $key) {
            self::assertArrayHasKey($key, $payload);
        }
        self::assertSame(1, $payload['exit_code']);
        self::assertContains('custom', array_column($payload['checkers'], 'name'));

        // Enterprise additions.
        self::assertSame(1, $payload['schema_version']);
        self::assertSame('failed', $payload['overall_status']);
        self::assertSame('error', $payload['fail_on']);
        self::assertSame('low', $payload['min_confidence']);
        self::assertSame(1.75, $payload['duration_total']);
    }

    public function testJsonPreservesUnicode(): void
    {
        $results = [
            new CheckResult('custom', 'failed', 0.1, [
                new Issue('TODO_FIXME', 'Grüße aus München', 'app/X.php', 1, Severity::Info, 'custom'),
            ], null, null),
        ];

        (new JsonReporter())->render($results, $this->context());

        $raw = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json');
        self::assertStringContainsString('Grüße aus München', $raw);
    }

    /** MarkdownReporter */

    public function testMarkdownHasTocMetadataAndFullSummary(): void
    {
        (new MarkdownReporter())->render($this->sampleResults(), $this->context());

        $md = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.md');

        self::assertStringContainsString('# Laravel Quality Report', $md);
        self::assertStringContainsString('## Contents', $md);
        self::assertStringContainsString('- [Summary](#summary)', $md);
        self::assertStringContainsString('- [Per-Checker](#per-checker)', $md);
        self::assertStringContainsString('- [custom](#custom)', $md);
        self::assertStringContainsString('**Tier:** quality', $md);
        self::assertStringContainsString('**Fail on:** error', $md);
        self::assertStringContainsString('| Error | 0 |', $md);
        self::assertStringContainsString('| Warning | 0 |', $md);
        self::assertStringContainsString('| Info | 1 |', $md);
        self::assertStringContainsString('<details>', $md);
        self::assertStringContainsString('### `app/Http/Controllers/UserController.php`', $md);
    }

    /** ConsoleReporter */

    public function testConsoleShowsGateConfigGroupsByFileAndHintsOnFailure(): void
    {
        $output = new BufferedOutput();
        $ctx = $this->context();
        $ctx->exitCode = 1;

        (new ConsoleReporter($output))->render($this->sampleResults(), $ctx);

        $text = $output->fetch();

        self::assertStringContainsString('Laravel Quality Checker', $text);
        self::assertStringContainsString('Tier: quality | Fail-on: error | Min-confidence: low', $text);
        self::assertStringContainsString('Issues — custom:', $text);
        self::assertStringContainsString('app/Http/Controllers/UserController.php', $text);
        self::assertStringContainsString('SQL_INJECTION', $text);
        self::assertStringContainsString('--format=json', $text);
    }

    public function testConsoleCapsIssuesPerChecker(): void
    {
        $issues = [];
        for ($i = 1; $i <= 60; ++$i) {
            $issues[] = new Issue('TODO_FIXME', 'Marker ' . $i, 'app/X.php', $i, Severity::Info, 'custom');
        }
        $results = [new CheckResult('custom', 'failed', 0.1, $issues, null, null)];

        $output = new BufferedOutput();
        (new ConsoleReporter($output))->render($results, $this->context());

        $text = $output->fetch();

        self::assertStringContainsString('Marker 50', $text);
        self::assertStringNotContainsString('Marker 51', $text);
        self::assertStringContainsString('and 10 more issue(s)', $text);
    }

    public function testConsoleQuietModePrintsSummaryLineOnly(): void
    {
        $output = new BufferedOutput();
        $ctx = $this->context();
        $ctx->quiet = true;

        (new ConsoleReporter($output))->render($this->sampleResults(), $ctx);

        $text = $output->fetch();

        self::assertStringContainsString('quality-checker:', $text);
        self::assertStringNotContainsString('Issues —', $text);
    }
}
