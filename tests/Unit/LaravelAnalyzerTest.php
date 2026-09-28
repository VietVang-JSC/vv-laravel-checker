<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use Rampart\QualityChecker\Analyzers\Laravel\RouteValidationAnalyzer;
use Rampart\QualityChecker\Result\Severity;

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

    public function testMigrationDestructiveUpRestoredInDownPasses(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->dropColumn('country_id'); }); }\n" .
            "    public function down(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->string('country_id')->nullable(); }); }\n" .
            "};\n",
            'database/migrations/2026_01_01_c.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testMigrationDestructiveUpWithoutRestoreFlagged(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->dropColumn('country_id'); }); }\n" .
            "    public function down(): void { Schema::dropIfExists('holidays_tmp'); }\n" .
            "};\n",
            'database/migrations/2026_01_01_d.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertContains('MIGRATION_DESTRUCTIVE_UP', $rules);
    }

    public function testMigrationIndexDropNotFlagged(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { Schema::table('pages', function (Blueprint \$t) { \$t->dropIndex('search'); \$t->dropIndex('name_search'); }); }\n" .
            "    public function down(): void { }\n" .
            "};\n",
            'database/migrations/2026_01_01_e.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertNotContains('MIGRATION_DESTRUCTIVE_UP', $rules);
    }

    public function testMigrationRawDropTableFlagged(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { DB::statement('DROP TABLE IF EXISTS sessions'); }\n" .
            "    public function down(): void { }\n" .
            "};\n",
            'database/migrations/2026_01_01_f.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertContains('MIGRATION_DESTRUCTIVE_UP', $rules);
    }

    public function testMigrationRawTruncateRestoredPasses(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { DB::unprepared('TRUNCATE TABLE temp_import'); }\n" .
            "    public function down(): void { Schema::create('temp_import', function (Blueprint \$t) { \$t->id(); }); }\n" .
            "};\n",
            'database/migrations/2026_01_01_g.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertNotContains('MIGRATION_DESTRUCTIVE_UP', $rules);
    }

    public function testMigrationRawAlterDropColumnFlagged(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { DB::statement('ALTER TABLE users DROP COLUMN ssn'); }\n" .
            "    public function down(): void { }\n" .
            "};\n",
            'database/migrations/2026_01_01_h.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertContains('MIGRATION_DESTRUCTIVE_UP', $rules);
    }

    public function testMigrationRawAlterDropColumnRestoredPasses(): void
    {
        $file = $this->temp(
            "<?php\nreturn new class extends Migration {\n" .
            "    public function up(): void { DB::statement('ALTER TABLE users DROP COLUMN ssn'); }\n" .
            "    public function down(): void { Schema::table('users', function (Blueprint \$t) { \$t->string('ssn')->nullable(); }); }\n" .
            "};\n",
            'database/migrations/2026_01_01_i.php'
        );

        $issues = (new MigrationAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);

        self::assertNotContains('MIGRATION_DESTRUCTIVE_UP', $rules);
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

    public function testRouteValidationSkipsUseImportedFormRequest(): void
    {
        // API-style: short type-hint resolved through the use-import
        // (no validate()/validated() call in the body at all).
        $file = $this->temp(
            "<?php\nnamespace App\\Api\\V1\\Controllers;\nuse App\\Api\\V1\\Requests\\StoreRequest;\n" .
            "class AccountController extends Controller {\n    public function store(StoreRequest \$request) {\n        return \$this->repository->store(\$request->getAllAccountData());\n    }\n}\n",
            'app/Api/V1/Controllers/AccountController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationStillFlagsPlainRequest(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n        return Order::create(\$request->getAllAccountData());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertSame('ROUTE_MISSING_VALIDATION', $issues[0]->rule);
    }

    public function testRouteValidationSkipsResolvedFormRequestWithRules(): void
    {
        // C: StoreUserRequest + rules() → validation evidence.
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\StoreUserRequest;\n" .
            "class UserController extends Controller {\n    public function store(StoreUserRequest \$request) {\n        return User::create(\$request->validated());\n    }\n}\n",
            'app/Http/Controllers/UserController.php'
        );
        $request = $this->temp(
            "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n" .
            "class StoreUserRequest extends FormRequest {\n" .
            "    public function authorize() {\n        return true;\n    }\n" .
            "    public function rules() {\n        return ['name' => 'required'];\n    }\n" .
            "}\n",
            'app/Http/Requests/StoreUserRequest.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$controller, $request]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationFlagsResolvedFormRequestWithoutRules(): void
    {
        // A resolved FormRequest with no rules() method validates nothing.
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\OpenRequest;\n" .
            "class AccountController extends Controller {\n    public function store(OpenRequest \$request) {\n        return Account::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/AccountController.php'
        );
        $request = $this->temp(
            "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n" .
            "class OpenRequest extends FormRequest {\n" .
            "    public function authorize() {\n        return true;\n    }\n" .
            "}\n",
            'app/Http/Requests/OpenRequest.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$controller, $request]);

        self::assertNotEmpty($issues);
        self::assertSame('ROUTE_MISSING_VALIDATION', $issues[0]->rule);
    }

    public function testRouteValidationSkipsDynamicRulesWithoutFields(): void
    {
        // F: dynamic rules() → layer present (no flag), fields unknown.
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Http\\Requests\\DynamicRequest;\n" .
            "class AccountController extends Controller {\n    public function store(DynamicRequest \$request) {\n        return Account::create(\$request->validated());\n    }\n}\n",
            'app/Http/Controllers/AccountController.php'
        );
        $request = $this->temp(
            "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Foundation\\Http\\FormRequest;\n" .
            "class DynamicRequest extends FormRequest {\n" .
            "    public function authorize() {\n        return true;\n    }\n" .
            "    public function rules() {\n        return config('app.rules');\n" .
            "    }\n" .
            "}\n",
            'app/Http/Requests/DynamicRequest.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$controller, $request]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationSkipsValidatorMake(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n" .
            "        \$v = \\Illuminate\\Support\\Facades\\Validator::make(\$request->all(), ['x' => 'required']);\n" .
            "        return Order::create(\$v->validated());\n" .
            "    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationSkipsValidatedUse(): void
    {
        // validated() alone marks validated-data use.
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n        return Order::create(\$request->validated());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testRouteValidationStillFlagsAllWithoutValidate(): void
    {
        // $request->validate() proves the layer; $request->all() alone
        // with no validate/validated/FormRequest still flags.
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController extends Controller {\n    public function store(Request \$request) {\n        \$data = \$request->all();\n        return Order::create(\$data);\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );

        $issues = (new RouteValidationAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertSame('ROUTE_MISSING_VALIDATION', $issues[0]->rule);
    }
}
