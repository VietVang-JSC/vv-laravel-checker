<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Semantic\LaravelSemanticIndex;

final class LaravelSemanticIndexTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            $this->removeDir($dir);
        }
        $this->dirs = [];
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * @param array<string, string> $files relPath => content
     * @return list<string> absolute paths
     */
    private function project(array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sem-' . uniqid('', true);
        @mkdir($dir, 0777, true);
        $this->dirs[] = $dir;
        $paths = [];
        foreach ($files as $rel => $content) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $content);
            $paths[] = $path;
        }

        return $paths;
    }

    public function testResolvesSimpleVerbRoute(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function store() {}\n}\n",
            'routes/web.php' => "<?php\nuse App\\Http\\Controllers\\BackupController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', [BackupController::class, 'store']);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\BackupController', 'store');

        self::assertCount(1, $routes);
        self::assertSame(['post'], $routes[0]->methods);
        self::assertSame('/backup', $routes[0]->uri);
        self::assertSame([], $routes[0]->middleware);
    }

    public function testMergesNestedGroupMiddleware(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(['web'])->group(function () {\n    Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {\n        Route::delete('/users/{user}', 'App\\\\Http\\\\Controllers\\\\UserController@destroy');\n    });\n});\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\UserController', 'destroy');

        self::assertCount(1, $routes);
        self::assertSame(['web', 'auth'], $routes[0]->middleware);
        self::assertSame('/admin/users/{user}', $routes[0]->uri);
        self::assertSame(['delete'], $routes[0]->methods);
    }

    public function testExpandsResourceRoutes(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse App\\Http\\Controllers\\PhotoController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::resource('photos', PhotoController::class);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'index'));
        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'store'));
        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'missing'));
        $show = $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'show');
        self::assertSame('/photos/{id}', $show[0]->uri);
    }

    public function testRespectsResourceOnlyExcept(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse App\\Http\\Controllers\\PhotoController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::resource('photos', PhotoController::class)->only(['index', 'show']);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'index'));
        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'store'));
    }

    public function testResolvesControllerGroup(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse App\\Http\\Controllers\\OrderController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::controller(OrderController::class)->group(function () {\n    Route::get('/orders', 'index');\n    Route::post('/orders', 'store');\n});\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\OrderController', 'index'));
        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\OrderController', 'store'));
    }

    public function testResolvesLegacyUsesSyntax(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/old', ['as' => 'old', 'uses' => 'App\\\\Http\\\\Controllers\\\\LegacyController@show']);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\LegacyController', 'show'));
    }

    public function testFollowsRequiredRouteFileWithStack(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(['auth'])->group(function () {\n    require __DIR__ . '/admin.php';\n});\n",
            'routes/admin.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/wipe', 'App\\\\Http\\\\Controllers\\\\AdminController@wipe');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\AdminController', 'wipe');

        self::assertCount(1, $routes);
        self::assertSame(['auth'], $routes[0]->middleware);
    }

    public function testFollowsBasePathRequireFromProvider(): void
    {
        $paths = $this->project([
            'routes/api.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\\\Http\\\\Controllers\\\\Api\\\\BackupController@store');\n",
            'app/Providers/RouteServiceProvider.php' => "<?php\nnamespace App\\Providers;\nuse Illuminate\\Support\\Facades\\Route;\nclass RouteServiceProvider {\n    public function boot(): void {\n        Route::group(['middleware' => 'auth:api', 'prefix' => 'api'], function () {\n            require base_path('routes/api.php');\n        });\n    }\n}\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\Api\\BackupController', 'store');

        self::assertCount(1, $routes);
        self::assertSame(['auth:api'], $routes[0]->middleware);
        self::assertSame('/api/backup', $routes[0]->uri);
    }

    public function testDescendsIntoInstallerGuard(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nif (file_exists(base_path('INSTALLERLOCK'))) {\n    Route::middleware(['auth'])->group(function () {\n        Route::post('/sort', 'App\\\\Http\\\\Controllers\\\\LinkController@sort');\n    });\n}\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\LinkController', 'sort'));
    }

    public function testShortNameFallback(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/x', 'BackupController@store');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\BackupController', 'store'));
    }

    public function testDynamicActionIsUnknown(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/x', ['App\\\\Http\\\\Controllers\\\\C', \$method]);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\C', 'show'));
        self::assertCount(0, $index->middlewareForAction('App\\Http\\Controllers\\C', 'show'));
    }

    public function testDynamicUriResolvesNull(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse App\\Http\\Controllers\\C;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/pages/' . strtolower(footer('Terms')), [C::class, 'show']);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\C', 'show');

        self::assertCount(1, $routes);
        self::assertNull($routes[0]->uri);
    }

    public function testMatchAndAnyVerbs(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::match(['get', 'post'], '/m', 'App\\\\Http\\\\Controllers\\\\C@multi');\nRoute::any('/a', 'App\\\\Http\\\\Controllers\\\\C@all');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $multi = $index->routesForAction('App\\Http\\Controllers\\C', 'multi');
        $all = $index->routesForAction('App\\Http\\Controllers\\C', 'all');

        self::assertCount(1, $multi);
        self::assertSame(['get', 'post'], $multi[0]->methods);
        self::assertCount(1, $all);
        self::assertContains('delete', $all[0]->methods);
    }

    public function testMiddlewareForActionMergesStacks(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/a', 'App\\\\Http\\\\Controllers\\\\C@go')->middleware('throttle:60,1');\nRoute::middleware(['auth'])->group(function () {\n    Route::post('/b', 'App\\\\Http\\\\Controllers\\\\C@go');\n});\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertSame(['throttle:60,1', 'auth'], $index->middlewareForAction('App\\Http\\Controllers\\C', 'go'));
    }

    public function testSameControllerThreeContextsDiffer(): void
    {
        $make = function (string $routes): array {
            return $this->project([
                'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => $routes,
            ]);
        };

        $strict = (new LaravelSemanticIndex())->build($make(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(['auth', 'can:admin'])->group(function () {\n    Route::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n});\n"
        ));
        $authOnly = (new LaravelSemanticIndex())->build($make(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(['auth'])->group(function () {\n    Route::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n});\n"
        ));
        $public = (new LaravelSemanticIndex())->build($make(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n"
        ));

        self::assertSame(['auth', 'can:admin'], $strict->middlewareForAction('App\\Http\\Controllers\\BackupController', 'store'));
        self::assertSame(['auth'], $authOnly->middlewareForAction('App\\Http\\Controllers\\BackupController', 'store'));
        self::assertSame([], $public->middlewareForAction('App\\Http\\Controllers\\BackupController', 'store'));
    }

    public function testApiResourceOmitsFormActions(): void
    {
        $paths = $this->project([
            'routes/api.php' => "<?php\nuse App\\Http\\Controllers\\PhotoController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::apiResource('photos', PhotoController::class);\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'store'));
        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'create'));
        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\PhotoController', 'edit'));
    }

    public function testRouteLineAndFileRecorded(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\BackupController', 'store');

        self::assertCount(1, $routes);
        self::assertStringEndsWith('routes' . DIRECTORY_SEPARATOR . 'web.php', $routes[0]->file);
        self::assertSame(3, $routes[0]->line);
    }

    public function testUnknownControllerYieldsNothing(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertSame([], $index->routesForAction('App\\Http\\Controllers\\Nope', 'store'));
        self::assertSame([], $index->middlewareForAction('App\\Http\\Controllers\\BackupController', 'destroy'));
    }

    public function testResolvesVariableConcatAction(): void
    {
        // Voyager shape: $namespacePrefix . 'X@login'.
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "\$namespacePrefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
                "Route::middleware(['auth'])->group(function () use (\$namespacePrefix) {\n" .
                "    Route::get('/user', \$namespacePrefix . 'UserController@show');\n" .
                "});\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $routes = $index->routesForAction('App\\Http\\Controllers\\UserController', 'show');

        self::assertCount(1, $routes);
        self::assertSame('/user', $routes[0]->uri);
        self::assertSame(['auth'], $routes[0]->middleware);
    }

    public function testDynamicActionStaysUnknown(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "\$controller = request('controller');\n" .
                "Route::get('/', \$controller);\n" .
                "Route::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);

        self::assertCount(0, $index->routesForAction('App\\Http\\Controllers\\BackupController', 'index'));
        self::assertCount(1, $index->routesForAction('App\\Http\\Controllers\\BackupController', 'store'));
        $coverage = $index->coverage();
        self::assertSame(2, $coverage['total']);
        self::assertSame(1, $coverage['resolved']);
        self::assertSame(1, $coverage['unknown']);
        self::assertSame(1, $coverage['reasons']['function-call'] ?? 0);
    }

    public function testConditionalVariableStaysUnknown(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "\$x = 'Admin';\n" .
                "if (\$condition) {\n" .
                "    \$x = 'User';\n" .
                "}\n" .
                "Route::get('/', \$x . 'Controller@index');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $coverage = $index->coverage();

        self::assertSame(1, $coverage['total']);
        self::assertSame(0, $coverage['resolved']);
        self::assertSame(1, $coverage['reasons']['conditional-assignment'] ?? 0);
    }

    public function testCoverageCountsFullAndPartial(): void
    {
        $paths = $this->project([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::post('/backup', 'App\\\\Http\\\\Controllers\\\\BackupController@store');\n" .
                "Route::get('/pages/' . strtolower('x'), 'App\\\\Http\\\\Controllers\\\\C@show');\n",
        ]);

        $index = (new LaravelSemanticIndex())->build($paths);
        $coverage = $index->coverage();

        self::assertSame(2, $coverage['total']);
        self::assertSame(2, $coverage['resolved']);
        self::assertSame(1, $coverage['full']);
        self::assertSame(1, $coverage['partial']);
        self::assertSame(0, $coverage['unknown']);
    }
}
