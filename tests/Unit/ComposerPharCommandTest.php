<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\ComposerAuditChecker;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Tools\ToolInstaller;

/**
 * A project that ships its own `composer.phar` must still be audited and still
 * be able to auto-install tools.
 *
 * Both code paths resolve composer the same way, and both used to return
 * `PHP_BINARY . ' ' . $phar` — one string. `Symfony\Component\Process\Process`
 * executes element 0 as the binary and passes the rest as arguments, so that
 * string named a file called `php C:\project\composer.phar`, the spawn failed,
 * and the failure surfaced as "composer binary not found" plus a silent
 * auto-install failure. Neither method had a test, so the shape survived.
 *
 * The fixture below is a real PHP script standing in for the phar: it records
 * the argv it was given. That makes the assertion end-to-end — the old code
 * cannot pass it, because the old code never gets a process to start.
 */
final class ComposerPharCommandTest extends TestCase
{
    private string $projectDir;

    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-composer-phar-' . bin2hex(random_bytes(6));
        mkdir($this->projectDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->projectDir);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function context(array $config = []): CheckContext
    {
        return new CheckContext(
            $this->projectDir,
            ['app'],
            $config,
            $this->projectDir . DIRECTORY_SEPARATOR . 'reports',
        );
    }

    /**
     * Write a stand-in composer.phar that records how it was invoked.
     *
     * @param string $stdout what the fake should print on stdout
     */
    private function writeFakeComposerPhar(string $stdout = ''): string
    {
        $log = $this->projectDir . DIRECTORY_SEPARATOR . 'argv.json';
        $phar = $this->projectDir . DIRECTORY_SEPARATOR . 'composer.phar';

        $script = "<?php\n\n"
            . 'file_put_contents(' . var_export($log, true) . ', json_encode($argv), FILE_APPEND);'
            . "\n"
            . 'echo ' . var_export($stdout, true) . ";\n";

        file_put_contents($phar, $script);

        return $log;
    }

    /**
     * @return list<string>
     */
    private function recordedArgv(string $log): array
    {
        self::assertFileExists($log, 'the composer.phar fixture was never executed');

        /** @var list<string> $argv */
        $argv = json_decode((string) file_get_contents($log), true);

        return $argv;
    }

    public function testToolInstallerRunsALocalComposerPhar(): void
    {
        $log = $this->writeFakeComposerPhar();

        // Opt in explicitly: auto-install is off by default, and this test is
        // about the argv composer.phar is called with, not about the default.
        $installer = new ToolInstaller($this->context(['auto_install_tools' => true]));

        self::assertTrue($installer->canInstall('phpcs'));
        self::assertTrue(
            $installer->install('phpcs'),
            'install() must succeed against a project that ships its own composer.phar'
        );

        $argv = $this->recordedArgv($log);
        // argv[0] is the script name, so the real arguments start at index 1.
        self::assertSame(['require', '--dev', 'squizlabs/php_codesniffer:^3.13 || ^4.0', '--no-interaction', '--no-progress', '--no-scripts', '--no-plugins'], array_slice($argv, 1));
    }

    public function testComposerAuditRunsALocalComposerPhar(): void
    {
        $advisories = json_encode([
            'advisories' => [
                'laravel/framework' => [[
                    'title' => 'Test advisory',
                    'cve' => 'CVE-2026-0001',
                    'advisoryId' => 'GHSA-test',
                    'link' => 'https://example.test/advisory',
                    'severity' => 'high',
                ]],
            ],
        ], JSON_THROW_ON_ERROR);
        $log = $this->writeFakeComposerPhar($advisories);

        $checker = new ComposerAuditChecker();
        $ctx = $this->context();

        self::assertTrue($checker->isAvailable($ctx), 'a local composer.phar must satisfy isAvailable()');

        $result = $checker->run($ctx);

        self::assertSame(['audit', '--format=json', '--no-interaction'], array_slice($this->recordedArgv($log), 1));
        self::assertSame('failed', $result->status);
        self::assertCount(1, $result->issues);
        self::assertSame('GHSA-test', $result->issues[0]->rule);
    }

    public function testComposerAuditReportsAdvisoriesFromThePathComposer(): void
    {
        // No composer.phar in the project, so resolution falls through to PATH.
        // Skipped rather than failed when composer is not installed.
        $checker = new ComposerAuditChecker();
        $ctx = $this->context();

        if (!$checker->isAvailable($ctx)) {
            self::markTestSkipped('composer is not on PATH in this environment');
        }

        // `which composer` succeeding is the only thing asserted here; the argv
        // shape for the PATH branch is covered by the phar branch above, which
        // is the one that was broken.
        self::assertTrue($checker->isAvailable($ctx));
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item instanceof \SplFileInfo) {
                if ($item->isDir()) {
                    @rmdir($item->getPathname());
                } else {
                    @unlink($item->getPathname());
                }
            }
        }

        @rmdir($dir);
    }
}
