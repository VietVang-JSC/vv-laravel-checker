<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Reporters\HtmlReporter;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class HtmlReporterTest extends TestCase
{
    private string $tempDir = '';

    protected function tearDown(): void
    {
        if ($this->tempDir !== '' && is_dir($this->tempDir)) {
            @unlink($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.html');
            @rmdir($this->tempDir);
        }
        $this->tempDir = '';
    }

    private function renderHtml(): string
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-html-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        $results = [
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
            new CheckResult('phpcs', 'passed', 1.2, [], null, null),
        ];

        $ctx = new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            $this->tempDir,
            packageVersion: '1.0.0'
        );

        (new HtmlReporter())->render($results, $ctx);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.html';
        self::assertFileExists($file);

        return (string) file_get_contents($file);
    }

    public function testReportContainsSidebarToc(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('id="sidebar"', $html);
        self::assertStringContainsString('href="#summary"', $html);
        self::assertStringContainsString('href="#top-rules"', $html);
        self::assertStringContainsString('href="#owasp"', $html);
        self::assertStringContainsString('href="#checkers"', $html);
        self::assertStringContainsString('href="#checker-custom"', $html);
        self::assertStringContainsString('href="#checker-phpcs"', $html);
    }

    public function testSidebarHasInteractiveSeverityRuleAndFileFilters(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('data-side-sev="critical"', $html);
        self::assertStringContainsString('data-side-sev="info"', $html);
        self::assertStringContainsString('data-side-rule="sql_injection"', $html);
        self::assertStringContainsString('data-side-file="app/http/controllers/usercontroller.php"', $html);
        self::assertStringContainsString('Hot Files', $html);
        self::assertStringContainsString('Top Rules', $html);
        // Click handlers are wired in the bundled script.
        self::assertStringContainsString('[data-side-sev]', $html);
        self::assertStringContainsString('[data-side-rule]', $html);
        self::assertStringContainsString('[data-side-file]', $html);
    }

    public function testReportContainsOnPageSearchAndSeverityFilters(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('id="report-search"', $html);
        self::assertStringContainsString('id="match-count"', $html);
        self::assertStringContainsString('data-sev="critical"', $html);
        self::assertStringContainsString('data-sev="error"', $html);
        self::assertStringContainsString('data-sev="warning"', $html);
        self::assertStringContainsString('data-sev="info"', $html);
    }

    public function testIssueRowsCarrySearchableDataAttributes(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('data-severity="critical"', $html);
        self::assertStringContainsString('data-severity="info"', $html);
        self::assertStringContainsString('data-search="sql_injection', $html);
        self::assertStringContainsString('id="checker-custom"', $html);
    }

    public function testReportStaysSelfContained(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('Laravel Quality Report', $html);
        self::assertStringContainsString('<style>', $html);
        self::assertStringContainsString('<script>', $html);
        self::assertStringNotContainsString('src="http', $html);
        self::assertStringNotContainsString('href="http', $html);
        self::assertStringNotContainsString('@import', $html);
    }
}
