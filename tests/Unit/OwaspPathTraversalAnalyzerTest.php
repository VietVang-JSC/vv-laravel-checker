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

    public function testFlagsFileFacadeGetWithRequestDate(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\File;\nuse Illuminate\\Http\\Request;\n" .
            "class storageLogController extends Controller {\n    public function indexDate(Request \$request) {\n" .
            "        return File::get(storage_path('logs/laravel-' . \$request->date . '.log'));\n    }\n}\n",
            'app/Http/Controllers/storageLogController.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsConfigPathHelper(): void
    {
        $file = $this->temp(
            "<?php\nclass UpdaterService {\n    protected function writeVersion(string \$version): void {\n" .
            "        file_put_contents(config_path('version.php'), '{}');\n    }\n}\n",
            'app/Services/UpdaterService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsConfigAssignedVariable(): void
    {
        $file = $this->temp(
            "<?php\nclass SetupDocs {\n    protected function documentation(): void {\n" .
            "        if (! file_exists(\$database = config('database.connections.docs.database'))) {\n" .
            "            file_put_contents(\$database, '');\n" .
            "        }\n    }\n}\n",
            'app/Console/Commands/SetupDocumentation.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
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

    public function testSkipsNullsafeRealPath(): void
    {
        $file = $this->temp(
            "<?php\nclass ImageService {\n    public function store(\$file): string {\n        return (string) file_get_contents(\$file?->getRealPath());\n    }\n}\n",
            'app/Uploads/ImageService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsFileDeleteWithRequestName(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\File;\n" .
            "class TempFileController extends Controller {\n    public function destroy(\\Illuminate\\Http\\Request \$request): void {\n        File::delete(storage_path('tmp/' . \$request->name));\n    }\n}\n",
            'app/Http/Controllers/TempFileController.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsTempnamBackedUnlink(): void
    {
        $file = $this->temp(
            "<?php\nclass ExportHelper {\n    public function stage(string \$extension): ?string {\n" .
            "        \$tmp = tempnam(sys_get_temp_dir(), 'export');\n" .
            "        if (\$tmp === false) {\n            return null;\n        }\n" .
            "        @unlink(\$tmp);\n        return \$tmp;\n    }\n}\n",
            'app/Helpers/ExportHelper.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsPlainVariableUnlink(): void
    {
        $file = $this->temp(
            "<?php\nclass ExportHelper {\n    public function clean(string \$record): void {\n        @unlink(\$record);\n    }\n}\n",
            'app/Helpers/ExportHelper.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_PATH_TRAVERSAL', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsReaddirListing(): void
    {
        $file = $this->temp(
            "<?php\nclass ThemeService {\n    public function scan(): void {\n        if (\$handle = opendir('themes')) {\n            while (false !== (\$entry = readdir(\$handle))) {\n                \$text = file_get_contents('themes/' . \$entry . '/readme.md');\n            }\n        }\n    }\n}\n",
            'app/Services/ThemeService.php'
        );

        $issues = (new OwaspPathTraversalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }
}
