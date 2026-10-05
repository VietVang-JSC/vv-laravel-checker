<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Fixer\PhpcsFixer;
use Rampart\QualityChecker\Runner\CheckContext;

final class FixerTest extends TestCase
{
    public function testIsAvailableFalseWhenNoVendorBinPhpcbf(): void
    {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-fixer-' . bin2hex(random_bytes(6));
        mkdir($temp, 0777, true);

        try {
            $ctx = new CheckContext($temp, ['app'], [], $temp . '/reports', noCache: true);
            $fixer = new PhpcsFixer();

            self::assertFalse($fixer->isAvailable($ctx));
        } finally {
            $this->removeDir($temp);
        }
    }

/**
 * An empty basePath falls back to getcwd(), so availability follows the working
 * directory rather than the project. This used to assert `assertIsBool(...)`,
 * which cannot fail: the method is declared `: bool`. Deleting
 * `locateBinaryForContext()` outright would have left the suite green.
 */
    public function testEmptyBasePathFallsBackToTheWorkingDirectory(): void
    {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-fixer-cwd-' . bin2hex(random_bytes(6));
        mkdir($temp, 0777, true);
        $previous = getcwd();

        try {
            $fixer = new PhpcsFixer();

            self::assertTrue($fixer->isAvailable($this->context('')));

            // With a working directory that has no vendor/bin/phpcbf, the same
            // context must report unavailable — the fallback is the cwd.
            self::assertNotFalse(chdir($temp));
            self::assertFalse($fixer->isAvailable($this->context('')));
        } finally {
            if (is_string($previous)) {
                chdir($previous);
            }
            $this->removeDir($temp);
        }
    }

    public function testIsAvailableTrueWhenTheProjectShipsPhpcbf(): void
    {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-fixer-' . bin2hex(random_bytes(6));
        $bin = $temp . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin';
        mkdir($bin, 0777, true);
        file_put_contents($bin . DIRECTORY_SEPARATOR . 'phpcbf', "#!/bin/sh\n");

        try {
            self::assertTrue((new PhpcsFixer())->isAvailable($this->context($temp)));
        } finally {
            $this->removeDir($temp);
        }
    }

    /**
 * `fix()` used to resolve its own binary, ignoring the context that
 * `isAvailable()` had just checked: it preferred the *package's* bundled
 * phpcbf, so `--fix` rewrote a consumer's files with a different phpcbf version
 * than the one its findings came from. Passing the context pins it to the target.
 */
    public function testFixUsesTheContextsBinaryAndReportsWhenItIsMissing(): void
    {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-fixer-run-' . bin2hex(random_bytes(6));
        mkdir($temp, 0777, true);

        try {
            $ctx = $this->context($temp);

            $result = (new PhpcsFixer())->fix(['app'], 'PSR12', null, $ctx);

            self::assertSame(0, $result->filesFixed);
            self::assertStringContainsString('phpcbf binary not found', implode("\n", $result->errors));
            self::assertFalse($result->success());
            self::assertSame('', $result->output);
        } finally {
            $this->removeDir($temp);
        }
    }

    private function context(string $basePath): CheckContext
    {
        return new CheckContext(
            $basePath,
            ['app'],
            [],
            sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-fixer-reports',
            noCache: true
        );
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
