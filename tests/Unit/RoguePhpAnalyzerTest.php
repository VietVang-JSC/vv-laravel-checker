<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Security\RoguePhpAnalyzer;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContext;

final class RoguePhpAnalyzerTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-rogue-' . uniqid('', true);
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

    private function analyzer(string $root): RoguePhpAnalyzer
    {
        $analyzer = new RoguePhpAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($root);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    private function file(string $rel, string $content = "<?php\n"): string
    {
        $path = $this->tmp . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    public function testFlagsRoguePhpInPublic(): void
    {
        $this->file('public/shell.php');
        $issues = $this->analyzer($this->tmp)->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('ROGUE_PHP', $issues[0]->rule);
        self::assertSame(Severity::Critical, $issues[0]->severity);
    }

    public function testIgnoresIndexPhpAndNonPhp(): void
    {
        $this->file('public/index.php');
        $this->file('public/app.js', 'console.log(1);');
        self::assertSame([], $this->analyzer($this->tmp)->analyze([]));
    }

    public function testFindsNestedRoguePhp(): void
    {
        $this->file('public/index.php');
        $this->file('public/vendor/backdoor.php');
        $issues = $this->analyzer($this->tmp)->analyze([]);
        self::assertCount(1, $issues);
    }

    public function testSilentWithoutPublicDir(): void
    {
        self::assertSame([], $this->analyzer($this->tmp)->analyze([]));
    }
}
