<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Reporters\SarifReporter;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class SarifReporterTest extends TestCase
{
    private string $tempDir = '';

    protected function tearDown(): void
    {
        if ($this->tempDir !== '' && is_dir($this->tempDir)) {
            @unlink($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.sarif');
            @rmdir($this->tempDir);
        }
        $this->tempDir = '';
    }

    /**
     * @param CheckResult[] $results
     * @return array<string, mixed>
     */
    private function render(array $results): array
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sarif-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        $ctx = new CheckContext(
            '/project',
            ['app'],
            [],
            $this->tempDir,
            packageVersion: '1.0.0'
        );

        (new SarifReporter())->render($results, $ctx);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.sarif';
        self::assertFileExists($file);

        $payload = json_decode((string) file_get_contents($file), true);
        self::assertIsArray($payload);

        return $payload;
    }

    public function testProducesValidSarifEnvelope(): void
    {
        $payload = $this->render([]);

        self::assertSame('2.1.0', $payload['version']);
        self::assertStringContainsString('sarif-2.1.0', $payload['$schema']);
        self::assertArrayHasKey('runs', $payload);
        self::assertCount(1, $payload['runs']);

        $driver = $payload['runs'][0]['tool']['driver'];
        self::assertSame('vietvang/quality-checker', $driver['name']);
        self::assertSame('1.0.0', $driver['version']);
        self::assertArrayHasKey('rules', $driver);
    }

    public function testMapsSeverityToSarifLevelsAndIncludesLocation(): void
    {
        $results = [
            new CheckResult('custom', 'failed', 0.2, [
                new Issue(
                    'SQL_INJECTION',
                    'Tainted input flows into select().',
                    '/project/app/Http/Controllers/UserController.php',
                    14,
                    Severity::Critical,
                    'custom',
                    [],
                    Confidence::High
                ),
                new Issue(
                    'TODO_FIXME',
                    'Leftover TODO marker.',
                    '/project/app/Services/OrderService.php',
                    3,
                    Severity::Info,
                    'custom',
                    [],
                    Confidence::Low
                ),
                new Issue(
                    'LARAVEL_PITFALL',
                    'dd() left in production code.',
                    null,
                    null,
                    Severity::Warning,
                    'custom'
                ),
            ], null, null),
        ];

        $payload = $this->render($results);
        $run = $payload['runs'][0];

        $byRule = [];
        foreach ($run['results'] as $result) {
            $byRule[$result['ruleId']] = $result;
        }

        self::assertSame('error', $byRule['SQL_INJECTION']['level']);
        self::assertSame('note', $byRule['TODO_FIXME']['level']);
        self::assertSame('warning', $byRule['LARAVEL_PITFALL']['level']);

        // Relative URI with forward slashes, region startLine present.
        $location = $byRule['SQL_INJECTION']['locations'][0]['physicalLocation'];
        self::assertSame('app/Http/Controllers/UserController.php', $location['artifactLocation']['uri']);
        self::assertSame(14, $location['region']['startLine']);

        // Issue without a file has no locations (valid per SARIF).
        self::assertArrayNotHasKey('locations', $byRule['LARAVEL_PITFALL']);
    }

    public function testRegistersEachRuleOnceWithHighestSeverityDefault(): void
    {
        $results = [
            new CheckResult('custom', 'failed', 0.1, [
                new Issue('OWASP_SSRF', 'URL from user input.', '/project/a.php', 1, Severity::Warning, 'custom'),
                new Issue('OWASP_SSRF', 'URL from user input again.', '/project/b.php', 2, Severity::Error, 'custom'),
            ], null, null),
        ];

        $payload = $this->render($results);
        $rules = $payload['runs'][0]['tool']['driver']['rules'];

        $ssrf = null;
        foreach ($rules as $rule) {
            if ($rule['id'] === 'OWASP_SSRF') {
                $ssrf = $rule;
            }
        }

        self::assertNotNull($ssrf);
        self::assertSame('error', $ssrf['defaultConfiguration']['level']);
        self::assertContains('security', $ssrf['properties']['tags']);
        self::assertContains('owasp', $ssrf['properties']['tags']);
    }

    public function testTierAndExitCodePreservedInRunProperties(): void
    {
        $results = [
            new CheckResult('phpcs', 'passed', 0.5, [], null, null),
        ];

        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sarif-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        $ctx = new CheckContext('/project', ['app'], [], $this->tempDir, packageVersion: '1.0.0');
        $ctx->exitCode = 1;

        (new SarifReporter())->render($results, $ctx);

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.sarif'),
            true
        );

        self::assertSame(1, $payload['runs'][0]['properties']['exit_code']);
        self::assertSame('quality', $payload['runs'][0]['properties']['tier']);
    }
}
