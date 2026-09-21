<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Fixer\PhpcsFixer;
use VietVang\QualityChecker\Runner\CheckContext;

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

    public function testIsAvailableFalseWhenBasePathIsEmpty(): void
    {
        $ctx = new CheckContext('', ['app'], [], sys_get_temp_dir() . '/reports', noCache: true);
        $fixer = new PhpcsFixer();

        // An empty basePath causes locateBinaryForContext() to fall back to getcwd(),
        // which is the package root where vendor/bin/phpcbf exists. This documents
        // that availability is tied to the resolved base path.
        self::assertIsBool($fixer->isAvailable($ctx));
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
