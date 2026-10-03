<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Feature;

use PHPUnit\Framework\TestCase;

/**
 * The standalone binary must work from the layout `composer require` produces.
 *
 * `composer require rampart/quality-checker` installs the package at
 * `vendor/rampart/quality-checker` and puts `vendor/bin/quality-check` on the
 * consumer's PATH. Composer hoists dependencies, so there is no
 * `vendor/rampart/quality-checker/vendor/autoload.php` — the script looked only
 * there and exited with "Run 'composer install' in the quality-checker directory
 * first" for the exact install the README documents.
 *
 * Running the installed form inside this package's own test suite would need a
 * real Laravel application, so this builds the dependency layout directly: the
 * real script is copied into a fake `vendor/rampart/quality-checker/bin`, and a
 * fake project-root `vendor/autoload.php` delegates to the real one.
 */
final class StandaloneInstallLayoutTest extends TestCase
{
    private string $projectDir = '';

    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-install-' . uniqid('', true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->projectDir);
    }

    public function testBinaryRunsWhenInstalledAsADependency(): void
    {
        [$command, $exitCode, $stdout, $stderr] = $this->runBinary(['--help']);

        self::assertSame(0, $exitCode, 'Binary must start from the vendor/bin layout. stderr: ' . $stderr);
        self::assertStringContainsString('Usage:', $stdout);
        self::assertStringContainsString('--exclude-path', $stdout);
        self::assertStringNotContainsString('autoloader', $stderr);
    }

    public function testBinaryReportsTheInstalledVersion(): void
    {
        [$command, $exitCode, $stdout] = $this->runBinary([$this->projectDir, '--only=custom', '--no-cache']);

        // A report header must identify the version that produced it. When the
        // autoloader lookup failed the runner never started, so this also proves
        // the runner is reachable from the vendor layout.
        self::assertSame(0, $exitCode, $command);
        self::assertMatchesRegularExpression(
            '/Laravel Quality Checker (v\S+|\S+)/',
            $stdout,
            'Report header must carry a resolved package version.'
        );
    }

    public function testMissingAutoloaderFailsWithActionableMessage(): void
    {
        $binDir = $this->projectDir . '/vendor/rampart/quality-checker/bin';
        mkdir($binDir, 0777, true);
        copy(dirname(__DIR__, 2) . '/bin/quality-check', $binDir . '/quality-check');

        $binary = $binDir . '/quality-check';
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(
            [PHP_BINARY, $binary, '--help'],
            $descriptors,
            $pipes,
            $this->projectDir,
        );

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('composer install', $stderr);
        self::assertStringNotContainsString('Usage:', $stdout);
    }

    /**
     * @param list<string> $args
     * @return array{string, int, string, string}
     */
    private function runBinary(array $args): array
    {
        $binDir = $this->projectDir . '/vendor/rampart/quality-checker/bin';
        mkdir($binDir, 0777, true);
        copy(dirname(__DIR__, 2) . '/bin/quality-check', $binDir . '/quality-check');

        // The hoisted project-level autoloader: it delegates to this package's
        // real one, which is what Composer's vendor/autoload.php does for
        // installed dependencies.
        file_put_contents(
            $this->projectDir . '/vendor/autoload.php',
            '<?php return require ' . var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true) . ";\n"
        );

        $command = [PHP_BINARY, $binDir . '/quality-check', ...$args];
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($command, $descriptors, $pipes, $this->projectDir);

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [
            implode(' ', array_map('strval', $command)),
            $exitCode,
            $stdout,
            $stderr,
        ];
    }

    private function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($directory);
    }
}
