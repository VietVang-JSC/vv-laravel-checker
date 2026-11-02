<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Feature;

use PHPUnit\Framework\TestCase;

/**
 * Locks the CLI wiring for the three HTML audiences. Unit tests cover the
 * renderer; this proves the standalone flags actually produce the files and
 * that --client does not leave a dev report behind.
 */
final class HtmlVariantsCliTest extends TestCase
{
    private string $projectDir = '';

    private string $outputDir = '';

    protected function setUp(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-variants-' . uniqid('', true);
        $this->projectDir = $base . DIRECTORY_SEPARATOR . 'project';
        $this->outputDir = $base . DIRECTORY_SEPARATOR . 'out';
        @mkdir($this->projectDir . DIRECTORY_SEPARATOR . 'app', 0777, true);
        file_put_contents($this->projectDir . DIRECTORY_SEPARATOR . 'composer.json', '{"name":"acme/demo","require":{"php":"^8.1"}}');
        file_put_contents($this->projectDir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Clean.php', "<?php\n\$ok = 1;\n");
    }

    protected function tearDown(): void
    {
        $this->removeDirectory(dirname($this->projectDir));
    }

    public function testAllVariantsWritesThreeHtmlFiles(): void
    {
        $code = $this->runCli(['--all-variants']);

        self::assertSame(0, $code);
        foreach (['quality-report.html', 'quality-report-findings.html', 'quality-report-client.html'] as $name) {
            self::assertFileExists($this->outputDir . DIRECTORY_SEPARATOR . $name, $name . ' missing');
        }
        $dev = (string) file_get_contents($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report.html');
        $findings = (string) file_get_contents($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report-findings.html');
        $client = (string) file_get_contents($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report-client.html');
        self::assertStringContainsString('id="checkers"', $dev);
        self::assertStringContainsString('id="checkers"', $findings);
        self::assertStringNotContainsString('id="checkers"', $client);
        self::assertStringContainsString('RAMPART', $client);
    }

    public function testClientFlagWritesOnlyClientReport(): void
    {
        $code = $this->runCli(['--client']);

        self::assertSame(0, $code);
        self::assertFileExists($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report-client.html');
        self::assertFileDoesNotExist($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report.html');
    }

    public function testNoRemediationWritesFindingsAlias(): void
    {
        $code = $this->runCli(['--no-remediation']);

        self::assertSame(0, $code);
        self::assertFileExists($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report.html');
        self::assertFileExists($this->outputDir . DIRECTORY_SEPARATOR . 'quality-report-findings.html');
    }

    /**
     * @param list<string> $flags
     */
    private function runCli(array $flags): int
    {
        $bin = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'quality-check';
        $parts = [escapeshellarg(PHP_BINARY), escapeshellarg($bin), escapeshellarg($this->projectDir), '--format=html', '--fail-on=none', '--no-cache', '--output=' . escapeshellarg($this->outputDir)];
        foreach ($flags as $flag) {
            $parts[] = $flag;
        }
        $out = [];
        $code = 1;
        @exec(implode(' ', $parts) . ' 2>&1', $out, $code);

        return $code;
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
