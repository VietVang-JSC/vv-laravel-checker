<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Security\Taint\TaintEngine;

final class TaintEngineTest extends TestCase
{
    /** @var list<string> */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if ($file !== '' && file_exists($file)) {
                @unlink($file);
            }
        }
        $this->tempFiles = [];
    }

    private function tempPhp(string $content): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-taint-' . uniqid('', true) . '.php';
        file_put_contents($path, $content);
        $this->tempFiles[] = $path;

        return $path;
    }

    public function testFlagsTaintedVariableIntoSqlSink(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class SearchController {\n    public function index(Request \$request) {\n" .
            "        \$q = \$request->input('q');\n" .
            "        return DB::select('SELECT * FROM products WHERE name LIKE \"%' . \$q . '%\"');\n    }\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_SQL_INJECTION', $hits[0]['rule']);
    }

    public function testFlagsDirectSourceIntoSink(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class SearchController {\n    public function index(Request \$request) {\n" .
            "        return DB::select(\$request->input('q'));\n    }\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_SQL_INJECTION', $hits[0]['rule']);
    }

    public function testSkipsLiteralSinkArgument(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\n" .
            "class ReportController {\n    public function index() {\n" .
            "        return DB::select('SELECT * FROM products');\n    }\n}\n"
        );

        self::assertSame([], (new TaintEngine())->analyze([$file]));
    }

    public function testFlagsCommandInjectionSink(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nuse Illuminate\\Http\\Request;\n" .
            "class BackupService {\n    public function run(Request \$request): void {\n" .
            "        \$dir = \$request->input('dir');\n" .
            "        system('ls ' . \$dir);\n    }\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_COMMAND_INJECTION', $hits[0]['rule']);
        self::assertSame('Critical', $hits[0]['severity']);
    }

    public function testFlagsUnserializeSinkWithErrorSeverity(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nuse Illuminate\\Http\\Request;\n" .
            "class SessionService {\n    public function hydrate(Request \$request): void {\n" .
            "        \$payload = unserialize(\$request->input('data'));\n    }\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_UNSAFE_SERIALIZE', $hits[0]['rule']);
        self::assertSame('Error', $hits[0]['severity']);
    }

    public function testFlagsInterpolatedStringSink(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class SearchController {\n    public function index(Request \$request) {\n" .
            "        \$q = \$request->input('q');\n" .
            "        return DB::select(\"SELECT * FROM products WHERE name = '\$q'\");\n    }\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_SQL_INJECTION', $hits[0]['rule']);
    }

    public function testAnalyzesTopLevelFunction(): void
    {
        $file = $this->tempPhp(
            "<?php\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "function searchProducts(Request \$request) {\n" .
            "    \$q = \$request->input('q');\n" .
            "    return DB::select('SELECT * FROM products WHERE name = ' . \$q);\n}\n"
        );

        $hits = (new TaintEngine())->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_SQL_INJECTION', $hits[0]['rule']);
    }

    public function testSupportsCustomEntryPointAndSink(): void
    {
        $file = $this->tempPhp(
            "<?php\nfunction handle() {\n" .
            "    \$v = mySource();\n" .
            "    mySink(\$v);\n}\n"
        );

        $engine = new TaintEngine();
        $engine->setEntryPoints(['mySource']);
        $engine->addSink('TAINT_SQL_INJECTION', 'mySink');

        $hits = $engine->analyze([$file]);

        self::assertNotEmpty($hits);
        self::assertSame('TAINT_SQL_INJECTION', $hits[0]['rule']);
    }

    public function testIgnoresUnknownSinkRuleId(): void
    {
        $file = $this->tempPhp(
            "<?php\nfunction handle() {\n    mySink('literal');\n}\n"
        );

        $engine = new TaintEngine();
        $engine->addSink('NOT_A_REAL_RULE', 'mySink');

        self::assertSame([], $engine->analyze([$file]));
    }

    public function testSkipsUnparseableFile(): void
    {
        $file = $this->tempPhp("<?php\nthis is not valid php (((\n");

        self::assertSame([], (new TaintEngine())->analyze([$file]));
    }

    public function testSkipsMissingFile(): void
    {
        $missing = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-nope-' . uniqid('', true) . '.php';

        self::assertSame([], (new TaintEngine())->analyze([$missing]));
    }
}
