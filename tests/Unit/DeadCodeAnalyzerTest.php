<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Convention\DeadCodeAnalyzer;
use Rampart\QualityChecker\Result\Issue;

/**
 * DeadCodeAnalyzer had no test at all, which is why two impossible branches
 * (`$method->name instanceof Identifier`) sat in phpstan-baseline instead of
 * being deleted. Convention analyzers are default-off, so a silent regression
 * here would not surface in a normal run.
 */
final class DeadCodeAnalyzerTest extends TestCase
{
    /** @var list<string> */
    private array $tempFiles = [];

    private string $tempDir = '';

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-dead-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
        }
        $this->tempFiles = [];
        if ($this->tempDir !== '' && is_dir($this->tempDir)) {
            @rmdir($this->tempDir);
        }
        $this->tempDir = '';
    }

    private function tempPhp(string $content, string $relPath = 'Str.php'): string
    {
        $path = $this->tempDir . DIRECTORY_SEPARATOR . $relPath;
        file_put_contents($path, $content);
        $this->tempFiles[] = $path;

        return $path;
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyze(array $files): array
    {
        return (new DeadCodeAnalyzer())->analyze($files);
    }

    public function testUnreferencedPrivateMethodIsFlagged(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass Str\n{\n    private function unusedHelper(): int\n    {\n        return 1;\n    }\n}\n"
        )]);

        self::assertCount(1, $issues);
        self::assertSame('DEAD_CODE', $issues[0]->rule);
        self::assertStringContainsString('unusedHelper', $issues[0]->message);
        self::assertSame('info', $issues[0]->severity->value);
        self::assertSame('low', $issues[0]->confidence->value);
        self::assertSame('Str', $issues[0]->metadata['class'] ?? null);
        self::assertSame('unusedHelper', $issues[0]->metadata['method'] ?? null);
    }

    public function testUnreferencedProtectedMethodIsFlagged(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass Repo\n{\n    protected function neverCalled(): void\n    {\n    }\n}\n"
        )]);

        self::assertCount(1, $issues);
        self::assertSame('DEAD_CODE', $issues[0]->rule);
        self::assertStringContainsString('neverCalled', $issues[0]->message);
    }

    public function testCalledMethodIsNotFlagged(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass Str\n{\n    public function run(): void\n    {\n        \$this->usedHelper();\n    }\n"
            . "    private function usedHelper(): void\n    {\n    }\n}\n"
        )]);

        self::assertSame([], $issues);
    }

    public function testPublicAbstractAndMagicMethodsAreSkipped(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nabstract class Base\n{\n    public function publicApi(): void\n    {\n    }\n"
            . "    abstract protected function contract(): void;\n"
            . "    public function __toString(): string\n    {\n        return '';\n    }\n}\n"
        )]);

        self::assertSame([], $issues);
    }

    public function testLaravelLifecycleAndAccessorMethodsAreSkipped(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass User\n{\n    public static function boot(): void\n    {\n    }\n"
            . "    private function getNameAttribute(): ?string\n    {\n        return null;\n    }\n"
            . "    private function scopeActive(\$query)\n    {\n        return \$query;\n    }\n}\n"
        )]);

        self::assertSame([], $issues);
    }

    public function testStaticCallCountsAsReference(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass Str\n{\n    private static function shared(): int\n    {\n        return 1;\n    }\n"
            . "    public function use(): int\n    {\n        return self::shared();\n    }\n}\n"
        )]);

        self::assertSame([], $issues);
    }

    public function testEachUnreferencedMethodIsReportedSeparately(): void
    {
        $issues = $this->analyze([$this->tempPhp(
            "<?php\nclass Str\n{\n    private function alpha(): void\n    {\n    }\n"
            . "    private function beta(): void\n    {\n    }\n}\n"
        )]);

        self::assertCount(2, $issues);
        $methods = array_map(static fn (Issue $i): string => (string) ($i->metadata['method'] ?? ''), $issues);
        sort($methods);
        self::assertSame(['alpha', 'beta'], $methods);
    }

    public function testNonPhpFilesAreIgnored(): void
    {
        $analyzer = new DeadCodeAnalyzer();

        self::assertFalse($analyzer->supports('README.md'));
        self::assertTrue($analyzer->supports('app/Support/Str.php'));
    }

    public function testEmptyInputProducesNoIssues(): void
    {
        self::assertSame([], $this->analyze([]));
    }

    public function testUnparseableFileYieldsNoIssues(): void
    {
        $issues = $this->analyze([$this->tempPhp("<?php class Broken {")]);

        self::assertSame([], $issues);
    }
}
