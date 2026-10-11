<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\CustomAnalyzerChecker;
use Rampart\QualityChecker\Runner\CheckContext;
use ReflectionMethod;

/**
 * Frontend collectors honor `analyzers.max_file_kb` like PHP collection:
 * a huge non-minified bundle must never be read into the shared source
 * cache, and the skip must be counted (not silent).
 */
final class CollectorOversizedTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-collect-' . uniqid('', true);
        @mkdir($this->tmp, 0777, true);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->tmp, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $item) {
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($this->tmp);
        }
    }

    private function file(string $rel, string $content): void
    {
        $path = $this->tmp . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);
    }

    /**
     * @return array{list<string>, int}
     */
    private function collect(string $method): array
    {
        $ctx = new CheckContext($this->tmp, [], ['analyzers' => ['max_file_kb' => 1]], $this->tmp);
        $m = new ReflectionMethod(CustomAnalyzerChecker::class, $method);
        /** @var array{list<string>, int} $result */
        $result = $m->invoke(new CustomAnalyzerChecker(), $ctx);

        return $result;
    }

    public function testJsSkipsOversizedButKeepsSmall(): void
    {
        $this->file('resources/js/app.js', "console.log(1);\n");
        $this->file('resources/js/bundle.js', str_repeat('var xxxxxxxx=1;', 200)); // ~3KB
        [$files, $oversized] = $this->collect('collectJsFiles');
        self::assertCount(1, $files);
        self::assertStringEndsWith('app.js', $files[0]);
        self::assertSame(1, $oversized);
    }

    public function testCssSkipsOversized(): void
    {
        $this->file('public/css/app.css', ".a{color:red}\n");
        $this->file('public/css/huge.css', str_repeat('.x{color:#ffffff}', 200)); // ~3KB
        [$files, $oversized] = $this->collect('collectCssFiles');
        self::assertCount(1, $files);
        self::assertSame(1, $oversized);
    }

    public function testBladeSkipsOversized(): void
    {
        $this->file('resources/views/ok.blade.php', "@stack('s')\n");
        $this->file('resources/views/big.blade.php', str_repeat("<div>x</div>\n", 200)); // ~2.4KB
        [$files, $oversized] = $this->collect('collectBladeFiles');
        self::assertCount(1, $files);
        self::assertSame(1, $oversized);
    }

    public function testMinifiedStillExcludedWithoutOversizedCount(): void
    {
        $this->file('public/js/app.min.js', "console.log(1);\n");
        [$files, $oversized] = $this->collect('collectJsFiles');
        self::assertSame([], $files);
        self::assertSame(0, $oversized);
    }
}
