<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class OwaspAnalyzersTest extends TestCase
{
    private function temp(string $content, string $relPath): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-owasp-' . uniqid('', true);
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

    public function testAccessControlFlagsUnprotectedMutatingController(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class UserController extends Controller {\n    public function store(Request \$request) {\n        \$this->user()->save();\n    }\n}\n",
            'app/Http/Controllers/UserController.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BROKEN_ACCESS_CONTROL', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testAccessControlSkipsAbstractBaseClass(): void
    {
        $file = $this->temp(
            "<?php\nabstract class BaseController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'app/Http/Controllers/BaseController.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlSkipsNonControllerClass(): void
    {
        $file = $this->temp(
            "<?php\nclass BaseRepository {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'app/Repositories/BaseRepository.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlSkipsFormShowMethods(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nclass FormController extends Controller {\n    public function create() {\n        return view('orders.create');\n    }\n    public function edit(\$id) {\n        return view('orders.edit');\n    }\n}\n",
            'app/Http/Controllers/FormController.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlSkipsAuthorizedMutatingMethod(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class PostController extends Controller {\n    public function store(Request \$request) {\n        \$this->authorize('create', \$request->user());\n        \$post->save();\n    }\n}\n",
            'app/Http/Controllers/PostController.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSsrfFlagsDynamicUrlInFileGetContents(): void
    {
        $file = $this->temp(
            "<?php\n\$data = file_get_contents(\$request->input('url'));\n",
            'app/Services/ExternalService.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_SSRF', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testSsrfSkipsLiteralUrl(): void
    {
        $file = $this->temp(
            "<?php\n\$data = file_get_contents('https://fixed.example/x');\n",
            'app/Services/ExternalService.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSsrfFlagsDynamicGuzzleClientCall(): void
    {
        $file = $this->temp(
            "<?php\n\$response = \$client->get(\$request->input('target'));\n",
            'app/Services/ExternalService.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertContains('OWASP_SSRF', $this->rules($issues));
    }

    public function testSstiFlagsDynamicViewTemplate(): void
    {
        $file = $this->temp(
            "<?php\nreturn view(\$template);\n",
            'app/Http/Controllers/PageController.php'
        );

        $issues = (new OwaspSstiAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_SSTI', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testSstiSkipsLiteralViewTemplate(): void
    {
        $file = $this->temp(
            "<?php\nreturn view('emails.welcome');\n",
            'app/Http/Controllers/PageController.php'
        );

        $issues = (new OwaspSstiAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSstiSkipsLiteralAssignedVariable(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\nclass ExerciseController extends Controller {\n" .
            "    public function edit() {\n        \$viewName = 'backend.exercise.edit_catalog';\n        return view(\$viewName);\n    }\n}\n",
            'app/Http/Controllers/ExerciseController.php'
        );

        $issues = (new OwaspSstiAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSstiStillFlagsInputAssignedVariable(): void
    {
        $file = $this->temp(
            "<?php\n\$viewName = \$request->input('template');\nreturn view(\$viewName);\n",
            'app/Http/Controllers/PageController.php'
        );

        $issues = (new OwaspSstiAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_SSTI', $this->rules($issues)[0] ?? null);
    }

    public function testMisconfigFlagsDebugEnabledInConfigApp(): void
    {
        $file = $this->temp(
            "<?php\nreturn [\n    'debug' => true,\n    'env' => 'production',\n];\n",
            'config/app.php'
        );

        $issues = (new OwaspMisconfigurationAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_MISCONFIGURATION', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Warning, $issues[0]->severity ?? null);
        self::assertSame('debug', $issues[0]->metadata['kind'] ?? null);
    }

    public function testMisconfigFlagsCorsWildcardInConfigCors(): void
    {
        $file = $this->temp(
            "<?php\nreturn [\n    'allowed_origins' => ['*'],\n];\n",
            'config/cors.php'
        );

        $issues = (new OwaspMisconfigurationAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_MISCONFIGURATION', $this->rules($issues)[0] ?? null);
        self::assertSame('cors', $issues[0]->metadata['kind'] ?? null);
    }

    public function testMisconfigSkipsSeederPasswordOutsideConfig(): void
    {
        $file = $this->temp(
            "<?php\nclass DemoSeeder {\n    public function run() {\n        return ['password' => ''];\n    }\n}\n",
            'database/seeders/DemoSeeder.php'
        );

        $issues = (new OwaspMisconfigurationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testMisconfigSkipsDebugLookalikeOutsideConfig(): void
    {
        $file = $this->temp(
            "<?php\nclass Demo {\n    public function run() {\n        return ['debug' => true];\n    }\n}\n",
            'app/Console/Demo.php'
        );

        $issues = (new OwaspMisconfigurationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testCommandInjectionFlagsTaintedSystemCall(): void
    {
        $file = $this->temp(
            "<?php\nsystem(\$request->input('cmd'));\n",
            'app/Console/Commands/RunCommand.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_COMMAND_INJECTION', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Critical, $issues[0]->severity ?? null);
    }

    public function testCommandInjectionFlagsTaintedSymfonyProcess(): void
    {
        $file = $this->temp(
            "<?php\n\$process = new Symfony\\Component\\Process\\Process(\$request->input('cmd'));\n",
            'app/Console/Commands/RunCommand.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_COMMAND_INJECTION', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Critical, $issues[0]->severity ?? null);
    }

    public function testCommandInjectionSkipsLiteralCommand(): void
    {
        $file = $this->temp(
            "<?php\n\$out = shell_exec('ls -la');\n",
            'app/Console/Commands/RunCommand.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testXxeFlagsUnprotectedXmlSink(): void
    {
        $file = $this->temp(
            "<?php\n\$xml = simplexml_load_string(\$raw);\n",
            'app/Services/XmlParser.php'
        );

        $issues = (new OwaspXxeAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_XXE', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testXxeSkipsSinkGuardedByEntityLoader(): void
    {
        $file = $this->temp(
            "<?php\nlibxml_disable_entity_loader(true);\n\$xml = simplexml_load_string(\$raw);\n",
            'app/Services/XmlParser.php'
        );

        $issues = (new OwaspXxeAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testXxeSkipsSinkGuardedByLibxmlNonet(): void
    {
        $file = $this->temp(
            "<?php\n\$doc = new DOMDocument();\n\$doc->loadXML(\$raw, LIBXML_NONET);\n",
            'app/Services/XmlParser.php'
        );

        $issues = (new OwaspXxeAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlSkipsRouteMiddlewareProtectedAction(): void
    {
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'app/Http/Controllers/BackupController.php'
        );
        $routes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
            "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@store')->middleware('can:admin-only');\n",
            'routes/web.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$controller, $routes]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlSkipsGroupMiddlewareProtectedAction(): void
    {
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class BackupController extends Controller {\n    public function destroy() {\n        \$this->model->delete();\n    }\n}\n",
            'app/Http/Controllers/BackupController.php'
        );
        $routes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
            "Route::middleware(['checkLevel'])->group(function () {\n" .
            "    Route::post('/backup/delete', 'App\\Http\\Controllers\\BackupController@destroy');\n" .
            "});\n",
            'routes/web.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$controller, $routes]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlStillFlagsThrottleOnlyRoute(): void
    {
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class PushController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'app/Http/Controllers/PushController.php'
        );
        $routes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
            "Route::post('/push', 'App\\Http\\Controllers\\PushController@store')->middleware('throttle:forms');\n",
            'routes/web.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$controller, $routes]);

        self::assertSame('OWASP_BROKEN_ACCESS_CONTROL', $this->rules($issues)[0] ?? null);
    }

    public function testAccessControlRouteMiddlewareCanBeDisabled(): void
    {
        $controller = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'app/Http/Controllers/BackupController.php'
        );
        $routes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
            "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@store')->middleware('can:admin-only');\n",
            'routes/web.php'
        );

        $issues = (new OwaspAccessControlAnalyzer(false))->analyze([$controller, $routes]);

        self::assertSame('OWASP_BROKEN_ACCESS_CONTROL', $this->rules($issues)[0] ?? null);
    }

    public function testAccessControlSkipsControllerGroupWithRequiredFile(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-owasp-' . uniqid('', true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'routes', 0777, true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Http' . DIRECTORY_SEPARATOR . 'Controllers', 0777, true);

        $controller = $dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Http'
            . DIRECTORY_SEPARATOR . 'Controllers' . DIRECTORY_SEPARATOR . 'AttributeController.php';
        file_put_contents(
            $controller,
            "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class AttributeController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n"
        );

        $catalog = $dir . DIRECTORY_SEPARATOR . 'routes' . DIRECTORY_SEPARATOR . 'catalog-routes.php';
        file_put_contents(
            $catalog,
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\AttributeController;\n" .
            "Route::controller(AttributeController::class)->prefix('attributes')->group(function () {\n" .
            "    Route::post('create', 'store');\n" .
            "});\n"
        );

        $web = $dir . DIRECTORY_SEPARATOR . 'routes' . DIRECTORY_SEPARATOR . 'web.php';
        file_put_contents(
            $web,
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
            "Route::group(['middleware' => ['admin']], function () {\n" .
            "    require 'catalog-routes.php';\n" .
            "});\n"
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze([$controller, $catalog, $web]);

        self::assertCount(0, $issues);
    }

    public function testAccessControlDistinguishesSameNamedControllers(): void
    {
        $adminController = $this->temp(
            "<?php\nnamespace Webkul\\Admin\\Http\\Controllers\\Catalog;\n" .
            "class AttributeController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'packages/Webkul/Admin/src/Http/Controllers/Catalog/AttributeController.php'
        );
        $shopController = $this->temp(
            "<?php\nnamespace Webkul\\Shop\\Http\\Controllers\\Catalog;\n" .
            "class AttributeController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
            'packages/Webkul/Shop/src/Http/Controllers/Catalog/AttributeController.php'
        );
        $adminRoutes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse Webkul\\Admin\\Http\\Controllers\\Catalog\\AttributeController;\n" .
            "Route::middleware(['admin'])->group(function () {\n" .
            "    Route::controller(AttributeController::class)->group(function () {\n" .
            "        Route::post('create', 'store');\n" .
            "    });\n" .
            "});\n",
            'packages/Webkul/Admin/src/Routes/web.php'
        );
        $shopRoutes = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse Webkul\\Shop\\Http\\Controllers\\Catalog\\AttributeController;\n" .
            "Route::controller(AttributeController::class)->group(function () {\n" .
            "    Route::post('create', 'store');\n" .
            "});\n",
            'packages/Webkul/Shop/src/Routes/web.php'
        );

        $issues = (new OwaspAccessControlAnalyzer())->analyze(
            [$adminController, $shopController, $adminRoutes, $shopRoutes]
        );

        self::assertCount(1, $issues);
        self::assertStringContainsString('Shop', (string) ($issues[0]->file ?? ''));
    }

    public function testCommandInjectionSkipsEscapedShellArg(): void
    {
        $file = $this->temp(
            "<?php\n\$fromPath = trim((string) shell_exec('where ' . escapeshellarg(\$tool)));\n",
            'app/Services/BackupService.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testCommandInjectionSkipsProcessArgumentArray(): void
    {
        $file = $this->temp(
            "<?php\nclass BackupService {\n    public function create(): void {\n" .
            "        \$command = ['mysqldump', '-h', 'localhost'];\n" .
            "        \$process = new Symfony\\Component\\Process\\Process(\$command);\n" .
            "        \$process->run();\n    }\n}\n",
            'app/Services/BackupService.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testCommandInjectionSkipsTestPaths(): void
    {
        $file = $this->temp(
            "<?php\nsystem(\$request->input('cmd'));\n",
            'tests/Feature/RunCommandTest.php'
        );

        $issues = (new OwaspCommandInjectionAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSsrfSkipsFopenWriteMode(): void
    {
        $file = $this->temp(
            "<?php\n\$handle = fopen(\$fullPath, 'w');\n",
            'app/Jobs/ExportBankFileJob.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSsrfSkipsLocalPathVariable(): void
    {
        $file = $this->temp(
            "<?php\n\$contents = file_get_contents(\$source);\n",
            'app/Services/BackupService.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSsrfStillFlagsUrlVariable(): void
    {
        $file = $this->temp(
            "<?php\n\$data = file_get_contents(\$url);\n",
            'app/Services/ExternalService.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_SSRF', $this->rules($issues)[0] ?? null);
    }

    public function testSsrfSkipsTestPaths(): void
    {
        $file = $this->temp(
            "<?php\n\$data = file_get_contents(\$request->input('url'));\n",
            'tests/Feature/DownloadTest.php'
        );

        $issues = (new OwaspSsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testXxeSkipsTestPaths(): void
    {
        $file = $this->temp(
            "<?php\n\$xml = simplexml_load_string(\$raw);\n",
            'tests/Unit/GovEfileTest.php'
        );

        $issues = (new OwaspXxeAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }
}
