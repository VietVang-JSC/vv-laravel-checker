<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Frontend\BladeStackAnalyzer;
use Rampart\QualityChecker\Analyzers\Frontend\CssSyntaxAnalyzer;
use Rampart\QualityChecker\Analyzers\Frontend\JsSyntaxAnalyzer;

final class FrontendAnalyzerTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-front-' . uniqid('', true);
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

    private function file(string $rel, string $content): string
    {
        $path = $this->tmp . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    public function testJsDetectsUnbalancedBrace(): void
    {
        $f = $this->file('resources/js/app.js', "function foo() {\n  if (true) {\n    console.log('hi');\n  // missing closing }\n");
        $issues = (new JsSyntaxAnalyzer())->analyze([$f]);
        self::assertCount(1, $issues);
        self::assertSame('JS_SYNTAX_ERROR', $issues[0]->rule);
    }

    public function testJsIsSilentOnBalanced(): void
    {
        $f = $this->file('resources/js/ok.js', "function foo() { return {a: [1,2]}; }\n");
        self::assertSame([], (new JsSyntaxAnalyzer())->analyze([$f]));
    }

    public function testJsIgnoresStringContent(): void
    {
        $f = $this->file('resources/js/str.js', "const a = \"{ not a brace }\"; const b = '{ also not }';\n");
        self::assertSame([], (new JsSyntaxAnalyzer())->analyze([$f]));
    }

    public function testCssDetectsUnbalanced(): void
    {
        $f = $this->file('resources/css/app.css', ".a { color: red; \n .b { color: blue; }");
        $issues = (new CssSyntaxAnalyzer())->analyze([$f]);
        self::assertCount(1, $issues);
        self::assertSame('CSS_SYNTAX_ERROR', $issues[0]->rule);
    }

    public function testCssIsSilentOnBalanced(): void
    {
        $f = $this->file('resources/css/ok.css', ".a { color: red; } .b { margin: 0; }");
        self::assertSame([], (new CssSyntaxAnalyzer())->analyze([$f]));
    }

    public function testBladeStackOrphanPush(): void
    {
        $layout = $this->file('resources/views/layouts/app.blade.php', "<html>@stack('scripts')</html>");
        $view = $this->file('resources/views/pages/show.blade.php', "@push('scripts')\n<script>hi</script>\n@endpush");
        $orphan = $this->file('resources/views/pages/orphan.blade.php', "@push('missing')\n<script>x</script>\n@endpush");

        $issues = (new BladeStackAnalyzer())->analyze([$layout, $view, $orphan]);
        $orphans = array_filter($issues, fn ($i) => $i->metadata['kind'] === 'orphan_push');
        self::assertCount(1, $orphans);
        self::assertStringContainsString('missing', $orphans[array_key_first($orphans)]->message);
    }

    public function testBladeStackUnclosedPush(): void
    {
        $f = $this->file('resources/views/bad.blade.php', "@push('scripts')\n<script>hi</script>\n");
        $issues = (new BladeStackAnalyzer())->analyze([$f]);
        $unclosed = array_filter($issues, fn ($i) => $i->metadata['kind'] === 'unclosed_block');
        self::assertCount(1, $unclosed);
        self::assertStringContainsString('@endpush', $unclosed[array_key_first($unclosed)]->message);
    }

    public function testBladeStackIsSilentWhenMatched(): void
    {
        $layout = $this->file('resources/views/layouts/app2.blade.php', "@stack('scripts')");
        $view = $this->file('resources/views/pages/ok.blade.php', "@push('scripts')\n<script></script>\n@endpush");
        $issues = (new BladeStackAnalyzer())->analyze([$layout, $view]);
        $orphans = array_filter($issues, fn ($i) => $i->metadata['kind'] === 'orphan_push');
        $unclosed = array_filter($issues, fn ($i) => $i->metadata['kind'] === 'unclosed_block');
        self::assertCount(0, $orphans);
        self::assertCount(0, $unclosed);
    }
}
