<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\ResultCache;

final class ResultCacheTest extends TestCase
{
    private string $outputDir;

    protected function setUp(): void
    {
        $this->outputDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-cache-' . bin2hex(random_bytes(6));
        mkdir($this->outputDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->outputDir);
    }

    private function cache(): ResultCache
    {
        return new ResultCache(new CheckContext($this->outputDir, ['app'], [], $this->outputDir));
    }

    public function testPutThenGetReturnsSameData(): void
    {
        $cache = $this->cache();
        $data = ['name' => 'phpcs', 'status' => 'passed', 'issues' => []];

        $cache->put('key-a', $data, 3600);

        self::assertSame($data, $cache->get('key-a'));
    }

    public function testExpiredEntryReturnsNullViaExpiredJson(): void
    {
        $cache = $this->cache();
        $cacheDir = $this->outputDir . DIRECTORY_SEPARATOR . '.cache';
        mkdir($cacheDir, 0777, true);

        $path = $cacheDir . DIRECTORY_SEPARATOR . 'key-expired.json';

        $payload = json_encode([
            'expires_at' => time() - 10,
            'created_at' => time() - 100,
            'data' => ['name' => 'stale'],
        ]);

        file_put_contents($path, $payload);

        self::assertNull($cache->get('key-expired'));
    }

    public function testClearEmptiesCache(): void
    {
        $cache = $this->cache();
        $cache->put('key-a', ['name' => 'a'], 3600);
        $cache->put('key-b', ['name' => 'b'], 3600);

        $cache->clear();

        self::assertNull($cache->get('key-a'));
        self::assertNull($cache->get('key-b'));
    }

    public function testKeyDiffersForDifferentNamesAndPaths(): void
    {
        $cache = $this->cache();

        $k1 = $cache->key('phpcs', ['app'], []);
        $k2 = $cache->key('phpstan', ['app'], []);
        $k3 = $cache->key('phpcs', ['src'], []);
        $k4 = $cache->key('phpcs', ['app'], ['standard' => 'PSR12']);

        self::assertNotSame($k1, $k2);
        self::assertNotSame($k1, $k3);
        self::assertNotSame($k1, $k4);
    }

    public function testKeySameForSameInputs(): void
    {
        $cache = $this->cache();

        self::assertSame(
            $cache->key('phpcs', ['app'], []),
            $cache->key('phpcs', ['app'], [])
        );
    }

    public function testCodeVersionIsStableHexAndNonEmpty(): void
    {
        $v1 = ResultCache::codeVersion();
        $v2 = ResultCache::codeVersion();

        self::assertSame($v1, $v2);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $v1);
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
