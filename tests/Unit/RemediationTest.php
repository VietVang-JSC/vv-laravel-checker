<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use VietVang\QualityChecker\Remediation\RuleRemediation;
use VietVang\QualityChecker\Reporters\ConsoleReporter;
use VietVang\QualityChecker\Reporters\HtmlReporter;
use VietVang\QualityChecker\Reporters\JsonReporter;
use VietVang\QualityChecker\Reporters\MarkdownReporter;
use VietVang\QualityChecker\Reporters\SarifReporter;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

/**
 * Remediation catalog: every rule teaches the fix, not just the symptom.
 */
final class RemediationTest extends TestCase
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
                    'OWASP_SSRF',
                    'Potential SSRF: URL derived from user input flows into file_get_contents().',
                    'app/Services/ExternalService.php',
                    12,
                    Severity::Error,
                    'custom',
                    [],
                    Confidence::High
                ),
            ], null, '1 issue'),
        ];
    }

    private function context(): CheckContext
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-rem-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            $this->tempDir,
            packageVersion: '1.0.0'
        );
    }

    public function testCatalogEntriesHaveCompleteShape(): void
    {
        $all = RuleRemediation::all();

        self::assertGreaterThan(30, count($all));

        foreach ($all as $rule => $entry) {
            self::assertArrayHasKey('why', $entry, $rule);
            self::assertArrayHasKey('fix', $entry, $rule);
            self::assertArrayHasKey('docs', $entry, $rule);
            self::assertNotSame('', trim($entry['why']), $rule);
            self::assertNotSame('', trim($entry['fix']), $rule);
        }
    }

    public function testCatalogCoversAllOwaspRules(): void
    {
        foreach (
            [
            'OWASP_BROKEN_ACCESS_CONTROL', 'OWASP_SSRF', 'OWASP_SSTI',
            'OWASP_MISCONFIGURATION', 'OWASP_COMMAND_INJECTION', 'OWASP_XXE',
            'OWASP_OPEN_REDIRECT', 'OWASP_PATH_TRAVERSAL', 'OWASP_BLADE_XSS',
            ] as $rule
        ) {
            self::assertNotNull(RuleRemediation::for($rule), $rule);
        }
    }

    public function testUnknownRuleReturnsNull(): void
    {
        self::assertNull(RuleRemediation::for('NO_SUCH_RULE'));
        self::assertNull(RuleRemediation::helpMarkdown('NO_SUCH_RULE'));
    }

    public function testHelpMarkdownContainsWhyAndFix(): void
    {
        $help = RuleRemediation::helpMarkdown('OWASP_SSRF');

        self::assertNotNull($help);
        self::assertStringContainsString('```php', (string) $help);
    }

    public function testJsonIssuesCarryRemediation(): void
    {
        (new JsonReporter())->render($this->sampleResults(), $this->context());

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );
        $issue = $payload['checkers'][0]['issues'][0];

        self::assertSame('OWASP_SSRF', $issue['rule']);
        self::assertIsArray($issue['remediation']);
        self::assertStringContainsString('internal services', $issue['remediation']['why']);
        self::assertStringContainsString('allow-list', $issue['remediation']['fix']);
        self::assertArrayNotHasKey('why_vi', $issue['remediation']);
    }

    public function testMarkdownHasRemediationSection(): void
    {
        (new MarkdownReporter())->render($this->sampleResults(), $this->context());

        $md = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.md');

        self::assertStringContainsString('## Remediation', $md);
        self::assertStringContainsString('### `OWASP_SSRF`', $md);
        self::assertStringContainsString('```php', $md);
        self::assertStringContainsString('attacker', $md);
    }

    public function testConsolePrintsFixGuidance(): void
    {
        $output = new BufferedOutput();
        (new ConsoleReporter($output))->render($this->sampleResults(), $this->context());

        $text = $output->fetch();

        self::assertStringContainsString('Remediation (how to fix per rule):', $text);
        self::assertStringContainsString('[OWASP_SSRF]', $text);
        self::assertStringContainsString('internal services', $text);
    }

    public function testHtmlRuleGroupContainsFixBox(): void
    {
        (new HtmlReporter())->render($this->sampleResults(), $this->context());

        $html = (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.html');

        self::assertStringContainsString('fixbox', $html);
        self::assertStringContainsString('<strong>Fix:</strong>', $html);
        self::assertStringContainsString('allow-list', $html);
    }

    public function testSarifRuleHasHelpAndHelpUri(): void
    {
        (new SarifReporter())->render($this->sampleResults(), $this->context());

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.sarif'),
            true
        );
        $rules = $payload['runs'][0]['tool']['driver']['rules'];

        self::assertCount(1, $rules);
        self::assertStringContainsString('```php', $rules[0]['help']['text']);
        self::assertStringContainsString(
            'docs/false-positives.md#owasp_ssrf--owasp_command_injection--owasp_ssti',
            $rules[0]['helpUri']
        );
    }
}
