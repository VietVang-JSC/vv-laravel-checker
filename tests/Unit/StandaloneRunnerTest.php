<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Standalone\StandaloneRunner;
use Symfony\Component\Console\Output\BufferedOutput;

final class StandaloneRunnerTest extends TestCase
{
    private string $dir = '';

    private string $out = '';

    protected function tearDown(): void
    {
        foreach ([$this->out, $this->dir] as $root) {
            if ($root === '' || !is_dir($root)) {
                continue;
            }
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                $path = $item->getPathname();
                if (is_dir($path)) {
                    @rmdir($path);
                } else {
                    @unlink($path);
                }
            }
            @rmdir($root);
        }
        $this->dir = '';
        $this->out = '';
        parent::tearDown();
    }

    public function testHelpWithoutTarget(): void
    {
        $output = new BufferedOutput();
        $code = (new StandaloneRunner([]))->run($output, dirname(__DIR__, 2));

        self::assertSame(2, $code);
        self::assertStringContainsString('Usage:', $output->fetch());

        $help = new BufferedOutput();
        $helpCode = (new StandaloneRunner(['--help']))->run($help, dirname(__DIR__, 2));

        self::assertSame(0, $helpCode);
        self::assertStringContainsString('--format=', $help->fetch());
    }

    public function testMissingTargetIsExitTwo(): void
    {
        $output = new BufferedOutput();
        $code = (new StandaloneRunner(['/no/such/dir']))->run($output, dirname(__DIR__, 2));

        self::assertSame(2, $code);
    }

    public function testScansFixtureAndWritesJson(): void
    {
        $this->makeVulnerableApp();

        $output = new BufferedOutput();
        $code = (new StandaloneRunner([
            $this->dir,
            '--format=json',
            '--tier=security',
            '--fail-on=none',
            '--output=' . $this->out,
        ]))->run($output, dirname(__DIR__, 2));

        self::assertSame(0, $code);
        $file = $this->out . DIRECTORY_SEPARATOR . 'quality-report.json';
        self::assertFileExists($file);
        $payload = json_decode((string) file_get_contents($file), true);
        self::assertGreaterThan(0, $payload['summary']['total_issues']);
        self::assertNotSame(
            '0.0.0',
            $payload['package_version'],
            'Standalone reports used to be stamped 0.0.0 because the runner never resolved a version.'
        );
    }

    public function testAllFormatsWriteTheirArtifact(): void
    {
        $this->makeVulnerableApp();

        $output = new BufferedOutput();
        $code = (new StandaloneRunner([
            $this->dir,
            '--format=all',
            '--tier=security',
            '--fail-on=none',
            '--output=' . $this->out,
        ]))->run($output, dirname(__DIR__, 2));

        self::assertSame(0, $code);
        foreach (['json', 'html', 'md', 'sarif'] as $extension) {
            self::assertFileExists(
                $this->out . DIRECTORY_SEPARATOR . 'quality-report.' . $extension,
                'Missing report artifact for format: ' . $extension
            );
        }
    }

    public function testExcludePathKeepsFixtureFindingsOutOfTheScan(): void
    {
        $this->makeVulnerableApp('fixtures');

        $output = new BufferedOutput();
        $code = (new StandaloneRunner([
            $this->dir,
            '--format=json',
            '--tier=security',
            '--fail-on=none',
            '--exclude-path=*' . '/fixtures/*',
            '--output=' . $this->out,
        ]))->run($output, dirname(__DIR__, 2));

        self::assertSame(0, $code);
        $payload = json_decode(
            (string) file_get_contents($this->out . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );

        self::assertSame(0, $payload['summary']['total_issues']);
        self::assertStringContainsString(
            'excluded by analyzers.exclude_paths',
            (string) $payload['checkers'][0]['summary']
        );
    }

    /**
     * A controller with a mutating action and no authorization check, placed in
     * `app/Http` or in `app/Http/<subdir>` when $subdir is given.
     */
    private function makeVulnerableApp(string $subdir = ''): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-standalone-' . uniqid('', true);
        $this->out = $this->dir . DIRECTORY_SEPARATOR . 'out';
        $controllerDir = $this->dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Http'
            . ($subdir === '' ? '' : DIRECTORY_SEPARATOR . $subdir);
        @mkdir($controllerDir, 0777, true);
        file_put_contents(
            $controllerDir . DIRECTORY_SEPARATOR . 'UserController.php',
            "<?php\nnamespace App\\Http;\nclass UserController extends \\Controller {\n    public function destroy(\$id) { \\Order::find(\$id)->delete(); }\n}\n"
        );
    }
}
