<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use Rampart\QualityChecker\Reporters\ConsoleReporter;
use Rampart\QualityChecker\Reporters\HtmlReporter;
use Rampart\QualityChecker\Reporters\JsonReporter;
use Rampart\QualityChecker\Reporters\MarkdownReporter;
use Rampart\QualityChecker\Reporters\QualityScore;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

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

    public function testFailOnNoneReportsCompletedInsteadOfFailed(): void
    {
        $ctx = $this->context();
        $ctx->failOn = 'none';

        (new JsonReporter())->render($this->sampleResults(), $ctx);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        $payload = json_decode((string) file_get_contents($file), true);

        self::assertSame('completed', $payload['overall_status']);
    }

    public function testFailOnErrorKeepsFailedStatus(): void
    {
        $ctx = $this->context();
        $ctx->failOn = 'error';

        (new JsonReporter())->render($this->sampleResults(), $ctx);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        $payload = json_decode((string) file_get_contents($file), true);

        self::assertSame('failed', $payload['overall_status']);
    }

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

        // Action priority: per-issue level plus summary counts and legend.
        $issues = $payload['checkers'][0]['issues'];
        self::assertSame('P0', $issues[0]['priority']);
        self::assertSame('P3', $issues[1]['priority']);
        self::assertSame(1, $payload['summary']['p0']);
        self::assertSame(1, $payload['summary']['p3']);
        self::assertSame('P0', $payload['priority_legend'][0]['level']);
        self::assertSame('Security', $payload['risk_overview'][0]['category']);
        self::assertSame('Immediate', $payload['risk_overview'][0]['action']);
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
        self::assertStringContainsString('| P0 — fix before release | 1 |', $md);
        self::assertStringContainsString('| P3 — technical debt / backlog | 1 |', $md);
        self::assertStringContainsString('## Action Plan', $md);
        self::assertStringContainsString('## Risk Overview', $md);
        self::assertStringContainsString('| Security | 1 | critical | Immediate |', $md);
        self::assertStringContainsString('| Rule | Priority | Severity | Confidence | Line | Message |', $md);
        self::assertStringContainsString('<details>', $md);
        self::assertStringContainsString('### `app/Http/Controllers/UserController.php`', $md);
    }

    /**
 * The shields.io badge is what a README or a PR comment ends up showing, so a
 * wrong colour is a lie nobody in this repository would see: the markdown test
 * above asserts seventeen strings from the report and none of them was the badge.
 * All four status/colour arms are pinned here, because "green badge on a red
 * build" is the exact failure a test suite cannot be asked to catch later.
 */
    public function testMarkdownBadgeReflectsTheWorstSeverity(): void
    {
        // sampleResults() has one critical issue -> critical / red.
        (new MarkdownReporter())->render($this->sampleResults(), $this->context());

        $md = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.md');

        self::assertStringContainsString(
            '![Quality](https://img.shields.io/badge/quality-critical-red) | Issues: 2 | Critical: 1',
            $md
        );
    }

    /**
     * @param list<Issue> $issues
     */
    private function markdownFor(array $issues): string
    {
        $reporter = new MarkdownReporter();
        $reporter->render([new CheckResult('custom', 'failed', 0.1, $issues, null, null)], $this->context());

        return (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.md');
    }

    /**
     * @param list<Issue> $issues
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('badgeStates')]
    public function testMarkdownBadgeColoursEveryStatus(array $issues, string $status, string $colour): void
    {
        self::assertStringContainsString(
            sprintf('![Quality](https://img.shields.io/badge/quality-%s-%s)', $status, $colour),
            $this->markdownFor($issues)
        );
    }

    /**
     * @return array<string, array{0: list<Issue>, 1: string, 2: string}>
     */
    public static function badgeStates(): array
    {
        $make = static fn (Severity $severity): Issue => new Issue(
            'SQL_INJECTION',
            'message',
            'app/Services/OrderService.php',
            3,
            $severity,
            'custom'
        );

        return [
            'critical outranks everything' => [[$make(Severity::Critical)], 'critical', 'red'],
            'error is reported as failed' => [[$make(Severity::Error)], 'failed', 'red'],
            'warning' => [[$make(Severity::Warning)], 'warning', 'orange'],
            'info only still passes' => [[$make(Severity::Info)], 'passed', 'brightgreen'],
            'no issues' => [[], 'passed', 'brightgreen'],
        ];
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
        self::assertStringContainsString('[P0]', $text);
        self::assertStringContainsString('Action plan: P0 1 (fix before release)', $text);
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

    /** Priority P0-P3 (severity x confidence x dimension) */

    public function testPriorityMapping(): void
    {
        // P0: any critical, or security error at high confidence.
        self::assertSame('P0', QualityScore::priorityFor('TODO_FIXME', 'custom', 'critical', 'low'));
        self::assertSame('P0', QualityScore::priorityFor('OWASP_BLADE_XSS', 'custom', 'error', 'high'));
        // P1: any other security-dimension finding.
        self::assertSame('P1', QualityScore::priorityFor('OWASP_BLADE_XSS', 'custom', 'error', 'medium'));
        self::assertSame('P1', QualityScore::priorityFor('OWASP_BLADE_XSS', 'custom', 'warning', 'low'));
        self::assertSame('P1', QualityScore::priorityFor('CVE-2024-1', 'composer_audit', 'warning', 'high'));
        // P2: non-security error.
        self::assertSame('P2', QualityScore::priorityFor('ROUTE_MISSING_VALIDATION', 'custom', 'error', 'high'));
        // P3: non-security warning/info.
        self::assertSame('P3', QualityScore::priorityFor('MISSING_CONTROLLER_TEST', 'custom', 'warning', 'low'));
        self::assertSame('P3', QualityScore::priorityFor('TODO_FIXME', 'custom', 'info', 'low'));
    }

    public function testHtmlRendersPriorityColumnAndActionPlan(): void
    {
        $ctx = $this->context();

        (new HtmlReporter())->render($this->sampleResults(), $ctx);

        $html = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.html');

        // Sample: SQL_INJECTION critical/high (Security) -> P0; TODO_FIXME info/low -> P3.
        self::assertStringContainsString('>Priority<', $html);
        self::assertStringContainsString('>P0<', $html);
        self::assertStringContainsString('>P3<', $html);
        self::assertStringContainsString('id="action-plan"', $html);
        self::assertStringContainsString('Fix before release', $html);
        self::assertStringContainsString('data-priority="p0"', $html);
        self::assertStringContainsString('id="risk-overview"', $html);
        self::assertStringContainsString('>Security<', $html);
        self::assertStringContainsString('/100', $html);
        self::assertStringContainsString('Release Blockers', $html);
        self::assertStringContainsString('Release Gate: BLOCKED', $html);
    }

    public function testRiskOverviewSplitsSecurityFromBacklog(): void
    {
        $rows = QualityScore::riskOverview($this->sampleResults());
        $byCategory = [];
        foreach ($rows as $row) {
            $byCategory[$row['category']] = $row;
        }

        // SQL_INJECTION critical/high -> Security, highest critical, P0, Immediate.
        self::assertSame(1, $byCategory['Security']['findings']);
        self::assertSame('critical', $byCategory['Security']['highest']);
        self::assertSame(1, $byCategory['Security']['p0']);
        self::assertSame('Immediate', $byCategory['Security']['action']);
        // TODO_FIXME info/low -> Maintainability, P3, Backlog.
        self::assertSame(1, $byCategory['Maintainability']['findings']);
        self::assertSame(1, $byCategory['Maintainability']['p3']);
        self::assertSame('Backlog', $byCategory['Maintainability']['action']);
    }
}
