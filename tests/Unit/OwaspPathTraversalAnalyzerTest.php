<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class OwaspPathTraversalAnalyzerTest extends TestCase
{
    private function temp(string $content, string $relPath): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-traversal-' . uniqid('', true);
        $path = $dir . DIRECTORY_SEPARATOR . $relPath;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    /**
     * @param list<Issue> $issues
     * @return list<string>
     */
    private function rules(array $issues): array
    {
        return array_map(static fn ($i) => $i->rule, $issues);
    }

    public function testFlagsResponseDownloadWithStoragePathConcat(): void
    {
        $file = $this->temp(
            "<?php\nreturn response()->download(storage_path('docs/' . \$request->file));\n",
            'app/Http/Controllers/DownloadController.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testFlagsFileGetContentsWithVariable(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents(\$var);\n",
            'app/Services/FileService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testFlagsStorageGetWithVariable(): void
    {
        $file = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Storage;\n\$contents = Storage::get(\$name);\n",
            'app/Services/DocService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
    }

    public function testFlagsIncludeWithDynamicExpr(): void
    {
        $file = $this->temp(
            "<?php\ninclude \$file;\n",
            'app/Services/Loader.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsBasenameWrapped(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents(storage_path('app/' . basename(\$name)));\n",
            'app/Services/FileService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsLiteralPath(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents('docs/fixed.txt');\n",
            'app/Services/FileService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsStoragePathLiteralOnly(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents(storage_path('app/fixed.txt'));\n",
            'app/Services/FileService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsEnvLookup(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents(env('DOC_PATH'));\n",
            'app/Services/FileService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }
}
