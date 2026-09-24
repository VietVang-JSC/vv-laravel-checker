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

    private string $baseDir = '';

    protected function tearDown(): void
    {
        foreach ([$this->tempDir, $this->baseDir] as $dir) {
            if ($dir !== '' && is_dir($dir)) {
                $this->removeDir($dir);
            }
        }
        $this->tempDir = '';
        $this->baseDir = '';
    }

    private function removeDir(string $dir): void
    {
        $items = scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * @param array<string, mixed> $configOverrides
     */
    private function renderHtml(array $configOverrides = []): string
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-html-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);
        $this->baseDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-base-' . uniqid('', true);

        // Real source file so code snippets can be read from disk.
        $srcDir = $this->baseDir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Http' . DIRECTORY_SEPARATOR . 'Controllers';
        @mkdir($srcDir, 0777, true);
        $srcLines = [
            '<?php',
            '',
            'class UserController',
            '{',
            '    public function index()',
            '    {',
            '        $rows = DB::select("select * from users where q = " . $request->q);',
            '        return $rows;',
            '    }',
            '}',
        ];
        file_put_contents($srcDir . DIRECTORY_SEPARATOR . 'UserController.php', implode("\n", $srcLines));

        $results = [
            new CheckResult('custom', 'failed', 0.5, [
                new Issue(
                    'SQL_INJECTION',
                    'Tainted input flows into select().',
                    'app/Http/Controllers/UserController.php',
                    7,
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
                new Issue(
                    'OWASP_SSRF',
                    'URL from user input into file_get_contents.',
                    'app/Http/Controllers/UserController.php',
                    7,
                    Severity::Error,
                    'custom',
                    [],
                    Confidence::High
                ),
            ], null, '3 issues'),
            new CheckResult('phpcs', 'passed', 1.2, [], null, null),
        ];

        $config = array_replace_recursive(
            ['html' => ['repo_url' => null, 'branch' => 'main', 'code_context' => 3]],
            $configOverrides
        );

        $ctx = new CheckContext(
            $this->baseDir,
            ['app'],
            $config,
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

    public function testIssueGroupsAreCollapsibleDetails(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('<details class="issue-group"', $html);
        self::assertStringContainsString('data-file="app/Http/Controllers/UserController.php"', $html);
        self::assertStringContainsString('id="expand-all"', $html);
        self::assertStringContainsString('id="collapse-all"', $html);
        self::assertStringContainsString('details.issue-group', $html);
    }

    public function testFileLinksDefaultToVscodeDeepLinks(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('href="vscode://file/', $html);
        self::assertStringContainsString('UserController.php:7', $html);
        self::assertStringNotContainsString('href="https://', $html);
    }

    public function testFileLinksUseGitHubBlobWhenRepoUrlConfigured(): void
    {
        $html = $this->renderHtml([
            'html' => ['repo_url' => 'https://github.com/org/repo', 'branch' => 'develop'],
        ]);

        self::assertStringContainsString(
            'href="https://github.com/org/repo/blob/develop/app/Http/Controllers/UserController.php#L7"',
            $html
        );
    }

    public function testCodeSnippetsRenderWithContextLines(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('class="snippet-row"', $html);
        self::assertStringContainsString('<pre class="code">', $html);
        self::assertStringContainsString('class="row cur"', $html);
        self::assertStringContainsString('DB::select', $html);
        self::assertStringContainsString('.snip-btn', $html);
        // 3 lines of context around line 7: lines 4..10 (numbers are padded).
        self::assertStringContainsString('<span class="cl"> 4</span>', $html);
        self::assertStringContainsString('<span class="cl">10</span>', $html);
    }

    public function testSnippetsCanBeDisabledViaConfig(): void
    {
        $html = $this->renderHtml(['html' => ['code_context' => 0]]);

        self::assertStringNotContainsString('<pre class="code">', $html);
        self::assertStringNotContainsString('class="snippet-row"', $html);
    }

    public function testSortableTableHooksExist(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('th[data-sortable]', $html);
        self::assertStringContainsString('data-type="num"', $html);
        self::assertStringContainsString('data-type="sev"', $html);
        self::assertStringContainsString('function sortTable', $html);
    }

    public function testChartsAndThemeTogglePresent(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('class="stacked"', $html);
        self::assertStringContainsString('Severity distribution', $html);
        self::assertStringContainsString('class="bars"', $html);
        self::assertStringContainsString('id="theme-toggle"', $html);
        self::assertStringContainsString("localStorage.getItem('qc-theme')", $html);
        self::assertStringContainsString('@media print', $html);
    }

    public function testOwaspSectionIsCollapsibleDrillDown(): void
    {
        $html = $this->renderHtml();

        self::assertStringContainsString('<details class="owasp-rule"', $html);
        self::assertStringContainsString('data-q="owasp_ssrf"', $html);
        self::assertStringContainsString('UserController.php:7', $html);
    }
}
