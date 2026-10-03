<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Result\PackageVersion;

final class PackageVersionTest extends TestCase
{
    public function testDetectsTheInstalledPackageVersion(): void
    {
        $version = PackageVersion::detect();

        self::assertNotSame('', $version);
        self::assertNotSame(
            PackageVersion::FALLBACK,
            $version,
            'Composer runtime metadata is available, so the report header must not fall back.'
        );
    }

    public function testComposerJsonVersionWins(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-version-' . uniqid('', true);
        mkdir($dir, 0777, true);
        file_put_contents($dir . '/composer.json', json_encode(['name' => 'x/y', 'version' => '1.2.3']));

        try {
            self::assertSame('1.2.3', PackageVersion::detect($dir));
        } finally {
            @unlink($dir . '/composer.json');
            @rmdir($dir);
        }
    }

    public function testBlankComposerJsonVersionIsIgnored(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-version-' . uniqid('', true);
        mkdir($dir, 0777, true);
        file_put_contents($dir . '/composer.json', json_encode(['name' => 'x/y', 'version' => '  ']));

        try {
            self::assertNotSame('', PackageVersion::detect($dir));
        } finally {
            @unlink($dir . '/composer.json');
            @rmdir($dir);
        }
    }

    public function testMissingComposerJsonFallsBackToRuntimeMetadata(): void
    {
        $version = PackageVersion::detect(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-missing-' . uniqid('', true));

        self::assertNotSame(PackageVersion::FALLBACK, $version);
    }

    public function testLabelPrefixesReleasesButNotBranches(): void
    {
        self::assertSame('v0.7.0', PackageVersion::label('0.7.0'));
        self::assertSame('dev-main', PackageVersion::label('dev-main'));
        self::assertSame('v0.0.0', PackageVersion::label(PackageVersion::FALLBACK));
    }
}
