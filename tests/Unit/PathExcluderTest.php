<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Scanning\PathExcluder;

final class PathExcluderTest extends TestCase
{
    public function testEmptyExcluderMatchesNothing(): void
    {
        $excluder = new PathExcluder([]);

        self::assertTrue($excluder->isEmpty());
        self::assertFalse($excluder->excludes('/app/fixtures/Vuln.php'));
    }

    public function testGlobPatternMatchesWholePath(): void
    {
        $excluder = new PathExcluder(['*/fixtures/*']);

        self::assertTrue($excluder->excludes('/srv/app/tests/fixtures/VulnController.php'));
        self::assertFalse($excluder->excludes('/srv/app/tests/Unit/VulnController.php'));
    }

    public function testPlainPatternMatchesOnSegmentBoundariesOnly(): void
    {
        $excluder = new PathExcluder(['tests/fixtures']);

        self::assertTrue($excluder->excludes('/srv/app/tests/fixtures/app/Http/X.php'));
        self::assertFalse($excluder->excludes('/srv/app/tests/fixturesx/X.php'));
    }

    public function testMatchingIsCaseInsensitiveAndSeparatorAgnostic(): void
    {
        $excluder = new PathExcluder(['*/Fixtures/*', 'tests/fixtures']);

        self::assertTrue($excluder->excludes('C:\\srv\\app\\tests\\Fixtures\\Vuln.php'));
        self::assertTrue($excluder->excludes('C:/srv/app/tests/fixtures/Vuln.php'));
    }

    public function testNonStringAndBlankPatternsAreDropped(): void
    {
        $excluder = new PathExcluder(['  ', '', 'tests/fixtures', 'tests/fixtures', '42']);

        self::assertSame(['tests/fixtures', '42'], $excluder->patterns());
    }

    public function testFromConfigReadsAnalyzersExcludePaths(): void
    {
        $excluder = PathExcluder::fromConfig(['analyzers' => ['exclude_paths' => ['*/fixtures/*']]]);

        self::assertFalse($excluder->isEmpty());
        self::assertTrue($excluder->excludes('/app/tests/fixtures/A.php'));
    }

    public function testFromConfigToleratesMissingAndMalformedConfig(): void
    {
        self::assertTrue(PathExcluder::fromConfig([])->isEmpty());
        self::assertTrue(PathExcluder::fromConfig(['analyzers' => ['exclude_paths' => 'nope']])->isEmpty());
        self::assertTrue(PathExcluder::fromConfig(['analyzers' => 'nope'])->isEmpty());
    }

    public function testShippedConfigExcludesFixturesByDefault(): void
    {
        $config = require dirname(__DIR__, 2) . '/config/quality-checker.php';
        $excluder = PathExcluder::fromConfig($config);

        self::assertFalse(
            $excluder->isEmpty(),
            'Fixtures are the one directory that must be excluded out of the box: '
            . 'code under fixtures/ exists to be vulnerable.'
        );
        self::assertTrue($excluder->excludes('/srv/project/tests/Feature/fixtures/app/Http/Controllers/VulnController.php'));
    }
}
