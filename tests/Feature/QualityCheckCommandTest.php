<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Feature;

use Orchestra\Testbench\TestCase;
use VietVang\QualityChecker\QualityCheckerServiceProvider;

final class QualityCheckCommandTest extends TestCase
{
    private string $tempDir = '';
    private string $fixturesDir = '';
    private string $appDir = '';
    private string $servicesDir = '';

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-reports-' . uniqid('', true);
        $this->fixturesDir = realpath(__DIR__ . '/fixtures') ?: (__DIR__ . '/fixtures');
        $this->appDir = $this->fixturesDir . DIRECTORY_SEPARATOR . 'app';
        $this->servicesDir = $this->appDir . DIRECTORY_SEPARATOR . 'Services';

        parent::setUp();
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->removeDirectory($this->tempDir);
        }

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [QualityCheckerServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $config = $app['config']->get('quality-checker', []);

        $config['output_dir'] = $this->tempDir;
        $config['paths'] = ['app'];
        // Do not attempt to composer-require missing tools during tests.
        $config['auto_install_tools'] = false;

        $app['config']->set('quality-checker', $config);
    }

    public function testCommandExistsAndIsRegistered(): void
    {
        $kernel = $this->app->make('Illuminate\Contracts\Console\Kernel');
        $method = new \ReflectionMethod($kernel, 'getArtisan');

        $this->assertTrue($method->invoke($kernel)->has('quality:check'));
    }

    public function testCustomCheckerFailsOnCriticalIssues(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
        ])->assertExitCode(1);
    }

    public function testFailOnCriticalIsNotMetByWarningOnlyRun(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->servicesDir],
            '--fail-on' => 'critical',
        ])->assertExitCode(0);
    }

    public function testJsonFormatProducesValidReport(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
        ])->assertExitCode(1);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        $this->assertFileExists($file);

        $payload = json_decode((string) file_get_contents($file), true);
        $this->assertIsArray($payload);
        $this->assertArrayHasKey('exit_code', $payload);
        $this->assertArrayHasKey('summary', $payload);
        $this->assertArrayHasKey('checkers', $payload);
        $this->assertSame(1, $payload['exit_code']);

        $this->assertIsArray($payload['checkers']);
        $names = array_column($payload['checkers'], 'name');
        $this->assertContains('custom', $names);
    }

    public function testHtmlFormatProducesReport(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'html',
            '--output' => $this->tempDir,
        ])->assertExitCode(1);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.html';
        $this->assertFileExists($file);
        $this->assertStringContainsString('Laravel Quality Report', (string) file_get_contents($file));
        $this->assertStringContainsString('SQL_INJECTION', (string) file_get_contents($file));
    }

    public function testMarkdownFormatProducesReport(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'md',
            '--output' => $this->tempDir,
        ])->assertExitCode(1);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.md';
        $this->assertFileExists($file);
        $this->assertStringContainsString('# Laravel Quality Report', (string) file_get_contents($file));
    }

    public function testConsoleFormatPrintsSummary(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'console',
            '--output' => $this->tempDir,
        ])->assertExitCode(1)->expectsOutputToContain('Laravel Quality Checker');
    }

    public function testOnlyPhpcsPhpstanSkipsCustomChecker(): void
    {
        // `phpcs`/`phpstan` are installed in the package's vendor, so they run for
        // real here (exit code may be 0 or 1 depending on the skeleton); the point
        // is that `custom` is NOT run when filtered out via --only.
        $this->artisan('quality:check', [
            '--only' => 'phpcs,phpstan',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
        ])->run();

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        $this->assertFileExists($file);

        $payload = json_decode((string) file_get_contents($file), true);
        $this->assertIsArray($payload);
        $names = array_column($payload['checkers'], 'name');
        $this->assertNotContains('custom', $names);
        $this->assertContains('phpcs', $names);
        $this->assertContains('phpstan', $names);
    }

    public function testBaselineGenerateWritesBaselineFile(): void
    {
        $baseline = $this->tempDir . DIRECTORY_SEPARATOR . 'baseline.json';

        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
            '--baseline-generate' => true,
            '--baseline-file' => $baseline,
        ])->assertExitCode(1);

        $this->assertFileExists($baseline);
        $baselineData = json_decode((string) file_get_contents($baseline), true);
        $this->assertArrayHasKey('baseline', $baselineData);
        $this->assertNotEmpty($baselineData['baseline']);
    }

    public function testBaselineFilteringExcludesKnownIssues(): void
    {
        $baseline = $this->tempDir . DIRECTORY_SEPARATOR . 'baseline.json';

        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
            '--baseline-generate' => true,
            '--baseline-file' => $baseline,
        ])->assertExitCode(1);

        $this->assertFileExists($baseline);

        // The baseline now matches the issues by signature; a correct implementation
        // filters them out and the quality gate passes (exit 0).
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
            '--baseline-file' => $baseline,
        ])->assertExitCode(0);

        $file = $this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json';
        $payload = json_decode((string) file_get_contents($file), true);

        $issues = [];
        foreach ($payload['checkers'] as $checker) {
            $issues = array_merge($issues, $checker['issues']);
        }
        $this->assertCount(0, $issues, 'All issues should be filtered out by the baseline.');
    }

    public function testFailOnNoneNeverFailsEvenWithCriticalIssues(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--fail-on' => 'none',
        ])->assertExitCode(0);
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($dir);
    }
}
