<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Feature;

use Orchestra\Testbench\TestCase;
use Rampart\QualityChecker\QualityCheckerServiceProvider;

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
        // These tests point --path at a deliberately vulnerable fixture app, so
        // the shipped `*/fixtures/*` default would (correctly) hide every
        // finding. Opting out here is what the override is for; the exclusion
        // itself is covered by testExcludePathKeepsFixturesOutOfTheScan below.
        $config['analyzers']['exclude_paths'] = [];

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

    public function testConfigFailOnIsHonouredWhenNoCliThresholdIsPassed(): void
    {
        // The fixture app has critical findings; with the shipped default
        // (error) this run fails. Relaxing the gate in config alone must be
        // enough to turn it green — the key used to be read by nobody.
        $this->app['config']->set('quality-checker.fail_on', 'none');

        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
        ])->assertExitCode(0);
    }

    public function testCiModePinsErrorThresholdOverRelaxedConfig(): void
    {
        $this->app['config']->set('quality-checker.fail_on', 'none');

        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--ci' => true,
            '--output' => $this->tempDir,
        ])->assertExitCode(1);
    }

    public function testExplicitFailOnWinsOverCiMode(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--ci' => true,
            '--fail-on' => 'none',
            '--output' => $this->tempDir,
        ])->assertExitCode(0);
    }

    public function testExcludePathKeepsFixturesOutOfTheScan(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
            '--exclude-path' => ['*' . '/fixtures/*'],
        ])->assertExitCode(0);

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );

        $issues = [];
        $summary = '';
        foreach ($payload['checkers'] as $checker) {
            $issues = array_merge($issues, $checker['issues']);
            $summary .= (string) $checker['summary'];
        }

        $this->assertCount(
            0,
            $issues,
            'Excluded fixtures must not produce findings. Remaining: '
            . implode(', ', array_map(static fn (array $i): string => (string) $i['file'] . ':' . $i['line'], $issues))
        );
        $this->assertStringContainsString('excluded by analyzers.exclude_paths', $summary);
    }

    public function testScanIncludesFixturesWhenNothingIsExcluded(): void
    {
        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
        ])->assertExitCode(1);

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );

        $issues = [];
        foreach ($payload['checkers'] as $checker) {
            $issues = array_merge($issues, $checker['issues']);
        }

        $this->assertNotCount(0, $issues, 'Control case: the same scan does report without an exclusion.');
    }

    /**
     * `exclude` in config was declared but never read, so a project that listed
     * a checker there still ran it.
     */
    public function testConfigExcludeIsHonouredAndMergedWithTheFlag(): void
    {
        $config = $this->app['config']->get('quality-checker', []);
        $config['exclude'] = ['custom'];
        $this->app['config']->set('quality-checker', $config);

        $this->artisan('quality:check', [
            '--path' => [$this->appDir],
            '--format' => 'json',
            '--output' => $this->tempDir,
            '--fail-on' => 'none',
            '--exclude' => 'phpcs,phpstan',
        ])->assertExitCode(0);

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );

        $names = array_column($payload['checkers'], 'name');

        $this->assertNotContains(
            'custom',
            $names,
            'exclude in config was ignored, so the custom analyzer still ran.'
        );
        $this->assertNotContains('phpcs', $names, 'The --exclude flag was overridden by the config key.');
        $this->assertNotContains('phpstan', $names, 'The --exclude flag was overridden by the config key.');
    }

    /**
 * Exit code 3 is documented as a runtime failure inside the package. Without a
 * catch it surfaced as Symfony's generic error handling, which CI reads as a
 * quality failure (exit 1) rather than a crash.
 */
    public function testInternalErrorIsExitThreeNotAQualityFailure(): void
    {
        $config = $this->app['config']->get('quality-checker', []);
        // A scalar where the analyzer expects a list. The resulting error is
        // raised during the run, after the context has been built successfully,
        // which is exactly the window exit code 3 covers.
        $config['analyzers']['extra_middleware'] = 42;
        $this->app['config']->set('quality-checker', $config);

        $this->artisan('quality:check', [
            '--only' => 'custom',
            '--path' => [$this->appDir],
        ])->assertExitCode(3);
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
