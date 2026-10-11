<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Frontend\JsSyntaxAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\EolAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\PermsAnalyzer;
use Rampart\QualityChecker\Scanning\ScanContext;

final class OpsAnalyzerTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-ops-' . uniqid('', true);
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

    /** @param array<string, string> $require */
    private function eolWith(array $require): EolAnalyzer
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', json_encode(['require' => $require]));
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    private function permsWith(string $root): PermsAnalyzer
    {
        $analyzer = new PermsAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($root);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    public function testEolFiresOnLaravel11(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^11.0', 'php' => '^8.3'])->analyze([]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);
        self::assertContains('EOL_COMPONENT', $rules);
        self::assertCount(1, $issues);
    }

    public function testEolSilentOnLaravel12And13(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^12.0'])->analyze([]));
        self::assertSame([], $this->eolWith(['laravel/framework' => '^13.0'])->analyze([]));
    }

    public function testEolSilentWhenAnySupportedMajorAllowed(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^11.0|^12.0'])->analyze([]));
    }

    public function testEolFiresOnPhp81Pin(): void
    {
        $issues = $this->eolWith(['php' => '^8.1'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('EOL_COMPONENT', $issues[0]->rule);
    }

    public function testEolSilentOnPhp82AndOpenRange(): void
    {
        self::assertSame([], $this->eolWith(['php' => '^8.2'])->analyze([]));
        self::assertSame([], $this->eolWith(['php' => '>=8.1'])->analyze([]));
    }

    public function testEolSilentWithoutComposerJson(): void
    {
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testEolSilentOnInvalidJson(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', '{not json');
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testPermsSilentWhenNoSensitivePaths(): void
    {
        self::assertSame([], $this->permsWith($this->tmp)->analyze([]));
    }

    public function testPermsSkipsTestbenchSkeleton(): void
    {
        $fake = $this->tmp . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'orchestra'
            . DIRECTORY_SEPARATOR . 'testbench-core' . DIRECTORY_SEPARATOR . 'laravel';
        @mkdir($fake, 0777, true);
        self::assertSame([], $this->permsWith($fake)->analyze([]));
    }

    public function testJsCollectorParityMinifiedExcluded(): void
    {
        // collectJsFiles() mirrors supports(): minified bundles never scan.
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/js/app.min.js'));
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/build/assets/app-abc123.min.js'));
        self::assertTrue((new JsSyntaxAnalyzer())->supports('resources/js/app.js'));
    }
}
