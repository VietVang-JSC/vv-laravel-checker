<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use VietVang\QualityChecker\Analyzers\Laravel\RouteValidationAnalyzer;
use VietVang\QualityChecker\Result\Severity;

final class LaravelAnalyzerTest extends TestCase
{
    private function temp(string $content, string $relPath): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-lar-' . uniqid('', true);
        $path = $dir . DIRECTORY_SEPARATOR . $relPath;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    public function testMigrationMissingDownDetected(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n    public function up(): void {\n        Schema::create('x', function (Blueprint \$t) { \$t->id(); });\n    }\n};\n",
            'database/migrations/2026_01_01_a.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertContains('MIGRATION_MISSING_DOWN', $rules);
    }

    public function testMigrationWithDownAndSafeUpPasses(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n    public function up(): void { Schema::create('x', function (Blueprint \$t) { \$t->id(); }); }\n    public function down(): void { Schema::dropIfExists('x'); }\n};\n",
            'database/migrations/2026_01_01_b.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testMigrationOnlyConsideredInMigrationsDir(): void
    {
        $file = $this->temp(
            "<?php\nclass Foo { public function up() {} }\n",
            'app/Foo.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationFlagsMutatingWithoutValidation(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertSame('ROUTE_MISSING_VALIDATION', $issues[0]->rule);
        self::assertSame(Severity::Warning, $issues[0]->severity);
    }

    public function testRouteValidationSkipsFormRequestParam(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\StoreOrderRequest;\n" .
            "class OrderController extends Controller {\n    public function store(StoreOrderRequest \$request) {\n        return Order::create(\$request->validated());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationSkipsValidateCall(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n        \$request->validate(['x' => 'required']);\n        return Order::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationIgnoresReadMethods(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function index(Request \$request) {\n        return Order::all();\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }
}
