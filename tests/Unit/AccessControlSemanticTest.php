<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Semantic\MiddlewareTaxonomy;

/**
 * v0.3.2 semantic BAC: the same Controller@action under different route
 * contexts must yield different decisions, and one action behind several
 * routes must keep one decision per route context — never merged.
 */
final class AccessControlSemanticTest extends TestCase
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
        foreach ((scandir($dir) ?: []) as $item) {
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sem-bac-' . uniqid('', true);
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

    private function controller(): string
    {
        return "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class BackupController extends Controller {\n" .
            "    public function update() {\n" .
            "        \$this->model->save();\n" .
            "    }\n" .
            "}\n";
    }

    /**
     * @param list<Issue> $issues
     * @return list<string>
     */
    private function rules(array $issues): array
    {
        return array_map(static fn ($i) => $i->rule, $issues);
    }

    public function testThreeContextsDiverge(): void
    {
        $protected = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth', 'can:update,backup'])->group(function () {\n" .
                "    Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n" .
                "});\n",
        ]);
        $authOnly = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth'])->group(function () {\n" .
                "    Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n" .
                "});\n",
        ]);
        $public = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n",
        ]);

        $protectedIssues = (new OwaspAccessControlAnalyzer())->analyze($protected);
        $authIssues = (new OwaspAccessControlAnalyzer())->analyze($authOnly);
        $publicIssues = (new OwaspAccessControlAnalyzer())->analyze($public);

        // Route A: auth + can → protected, no finding.
        self::assertSame([], $this->rules($protectedIssues));

        // Route B: auth-only → review finding, medium confidence.
        self::assertCount(1, $authIssues);
        self::assertSame('review', $authIssues[0]->metadata['semantic_status'] ?? null);
        self::assertSame(Confidence::Medium, $authIssues[0]->confidence);
        self::assertSame(Severity::Error, $authIssues[0]->severity);

        // Route C: public → exposed finding, high confidence.
        self::assertCount(1, $publicIssues);
        self::assertSame('exposed', $publicIssues[0]->metadata['semantic_status'] ?? null);
        self::assertSame(Confidence::High, $publicIssues[0]->confidence);
    }

    public function testMultiRouteKeepsContextsSeparate(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "class UserController extends Controller {\n" .
                "    public function show() {\n" .
                "        \$this->model->save();\n" .
                "    }\n" .
                "}\n",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth', 'admin'])->group(function () {\n" .
                "    Route::get('/admin/users/{user}', 'App\\Http\\Controllers\\UserController@show');\n" .
                "});\n" .
                "Route::middleware(['auth:api'])->group(function () {\n" .
                "    Route::get('/api/users/{user}', 'App\\Http\\Controllers\\UserController@show');\n" .
                "});\n" .
                "Route::get('/preview/{user}', 'App\\Http\\Controllers\\UserController@show');\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        // Worst context wins: the single public route yields one EXPOSED
        // finding citing /preview — never merged into "has auth".
        self::assertCount(1, $issues);
        self::assertSame('exposed', $issues[0]->metadata['semantic_status'] ?? null);
        self::assertSame('/preview/{user}', $issues[0]->metadata['route']['uri'] ?? null);
        self::assertSame(['get'], $issues[0]->metadata['route']['methods'] ?? null);
    }

    public function testMultiRouteReviewWhenNoPublicRoute(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "class UserController extends Controller {\n" .
                "    public function show() {\n" .
                "        \$this->model->save();\n" .
                "    }\n" .
                "}\n",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth', 'admin'])->group(function () {\n" .
                "    Route::get('/admin/users/{user}', 'App\\Http\\Controllers\\UserController@show');\n" .
                "});\n" .
                "Route::middleware(['auth:api'])->group(function () {\n" .
                "    Route::get('/api/users/{user}', 'App\\Http\\Controllers\\UserController@show');\n" .
                "});\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertCount(1, $issues);
        self::assertSame('review', $issues[0]->metadata['semantic_status'] ?? null);
    }

    public function testUnknownRouteResolutionKeepsFailSafeFinding(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertCount(1, $issues);
        self::assertSame('unknown', $issues[0]->metadata['semantic_status'] ?? null);
        self::assertSame(Confidence::High, $issues[0]->confidence);
    }

    public function testCanMiddlewareIsAuthorizationEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update')->middleware('can:update,backup');\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame([], $this->rules($issues));
    }

    public function testPermissionAndRoleAreAuthorizationEvidence(): void
    {
        foreach (['permission:users.edit', 'role:admin'] as $middleware) {
            $paths = $this->project([
                'app/Http/Controllers/BackupController.php' => $this->controller(),
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                    "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update')->middleware('{$middleware}');\n",
            ]);

            self::assertSame([], $this->rules((new OwaspAccessControlAnalyzer())->analyze($paths)), $middleware);
        }
    }

    public function testVerifiedSignedThrottleAreNotAuthorization(): void
    {
        foreach (['verified', 'signed', 'throttle:60,1'] as $middleware) {
            $paths = $this->project([
                'app/Http/Controllers/BackupController.php' => $this->controller(),
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                    "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update')->middleware('{$middleware}');\n",
            ]);

            $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

            self::assertCount(1, $issues, $middleware);
            self::assertNotSame('protected', $issues[0]->metadata['semantic_status'] ?? null);
        }
    }

    public function testFindingCarriesRouteEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['web'])->group(function () {\n" .
                "    Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n" .
                "});\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertCount(1, $issues);
        $meta = $issues[0]->metadata;
        self::assertSame('App\\Http\\Controllers\\BackupController', $meta['controller'] ?? null);
        self::assertSame('update', $meta['action'] ?? null);
        self::assertSame('/backup', $meta['route']['uri'] ?? null);
        self::assertSame(['post'], $meta['route']['methods'] ?? null);
        self::assertSame(['web'], $meta['middleware'] ?? null);
        self::assertSame([], $meta['authorization_evidence'] ?? null);
        self::assertSame('exposed', $meta['semantic_status'] ?? null);
    }

    public function testNestedGroupMiddlewareReachesDecision(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth'])->group(function () {\n" .
                "    Route::group(['middleware' => 'can:admin-only', 'prefix' => 'admin'], function () {\n" .
                "        Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n" .
                "    });\n" .
                "});\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        // Inherited can: through two group levels → protected.
        self::assertSame([], $this->rules($issues));
    }

    public function testMiddlewareAliasEvidenceSuppresses(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'app/Http/Kernel.php' => "<?php\nnamespace App\\Http;\n" .
                "use App\\Http\\Middleware\\CheckPermissions;\n" .
                "class Kernel {\n" .
                "    protected \$routeMiddleware = ['authorize' => CheckPermissions::class];\n" .
                "}\n",
            'app/Http/Middleware/CheckPermissions.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n" .
                "class CheckPermissions {\n" .
                "    public function handle(Request \$request, Closure \$next, \$section = null) {\n" .
                "        if (Gate::allows(\$section)) {\n" .
                "            return \$next(\$request);\n" .
                "        }\n" .
                "        return response()->view('x', [], 403);\n" .
                "    }\n" .
                "}\n",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth', 'authorize:superuser'])->group(function () {\n" .
                "    Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update');\n" .
                "});\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        // alias → CheckPermissions::handle() → Gate::allows + 403 → protected.
        self::assertSame([], $this->rules($issues));
    }

    public function testOwnershipMiddlewareStaysReviewGolden(): void
    {
        // Real-world golden case (Linkstack deleteLink): the `link-id`
        // middleware verifies ownership ($user->id vs $link->user_id) —
        // object-level authorization is out of scope, so this MUST stay
        // review and must never be silently suppressed.
        $paths = $this->project([
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "class UserController extends Controller {\n" .
                "    public function deleteLink(\\Illuminate\\Http\\Request \$request) {\n" .
                "        \\App\\Models\\Link::where('id', \$request->id)->delete();\n" .
                "        return redirect('/studio/links');\n" .
                "    }\n" .
                "}\n",
            'app/Http/Kernel.php' => "<?php\nnamespace App\\Http;\n" .
                "class Kernel {\n" .
                "    protected \$routeMiddleware = [\n" .
                "        'auth' => \\App\\Http\\Middleware\\Authenticate::class,\n" .
                "        'link-id' => \\App\\Http\\Middleware\\LinkId::class,\n" .
                "    ];\n" .
                "}\n",
            'app/Http/Middleware/LinkId.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Auth;\nuse Closure;\nuse App\\Models\\Link;\n" .
                "class LinkId {\n" .
                "    public function handle(\$request, Closure \$next) {\n" .
                "        \$link = Link::find(\$request->route('id'));\n" .
                "        if (!\$link) {\n" .
                "            return abort(404);\n" .
                "        }\n" .
                "        if (Auth::user()->id != \$link->user_id) {\n" .
                "            return abort(403);\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::middleware(['auth', 'link-id'])->group(function () {\n" .
                "    Route::get('/deleteLink/{id}', 'App\\Http\\Controllers\\UserController@deleteLink');\n" .
                "});\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertCount(1, $issues);
        self::assertSame('review', $issues[0]->metadata['semantic_status'] ?? null);
        $trails = $issues[0]->metadata['middleware_resolution'] ?? [];
        self::assertNotEmpty($trails);
        $linkId = null;
        foreach ($trails as $trail) {
            if (($trail['alias'] ?? null) === 'link-id') {
                $linkId = $trail;
            }
        }
        self::assertNotNull($linkId);
        self::assertSame('App\\Http\\Middleware\\LinkId', $linkId['class'] ?? null);
        self::assertSame('unrecognized', $linkId['mechanism'] ?? null);
    }

    public function testUnregisteredAliasStaysReviewWithTrail(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/BackupController.php' => $this->controller(),
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\n" .
                "Route::post('/backup', 'App\\Http\\Controllers\\BackupController@update')->middleware('owner');\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertCount(1, $issues);
        self::assertSame('review', $issues[0]->metadata['semantic_status'] ?? null);
        $trails = $issues[0]->metadata['middleware_resolution'] ?? [];
        self::assertSame('unregistered', $trails[0]['mechanism'] ?? null);
        self::assertSame('owner', $trails[0]['alias'] ?? null);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function taxonomyCases(): iterable
    {
        yield 'auth guard' => ['auth', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'auth:api guard' => ['auth:api', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'auth:web guard' => ['auth:web', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'sanctum' => ['sanctum', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'jwt.auth' => ['jwt.auth', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'edge api key' => ['edge.api.key', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'verified' => ['verified', MiddlewareTaxonomy::AUTHENTICATION];
        yield 'can ability' => ['can:update,post', MiddlewareTaxonomy::AUTHORIZATION];
        yield 'bare can' => ['can', MiddlewareTaxonomy::AUTHORIZATION];
        yield 'permission' => ['permission:users.edit', MiddlewareTaxonomy::AUTHORIZATION];
        yield 'role' => ['role:admin', MiddlewareTaxonomy::AUTHORIZATION];
        yield 'signed' => ['signed', MiddlewareTaxonomy::GATE];
        yield 'admin' => ['admin', MiddlewareTaxonomy::GATE];
        yield 'owner' => ['owner', MiddlewareTaxonomy::GATE];
        yield 'checkLevel' => ['checkLevel', MiddlewareTaxonomy::GATE];
        yield 'throttle' => ['throttle:60,1', MiddlewareTaxonomy::NONE];
        yield 'guest' => ['guest', MiddlewareTaxonomy::NONE];
        yield 'guestAdmin' => ['guestAdmin', MiddlewareTaxonomy::NONE];
        yield 'web' => ['web', MiddlewareTaxonomy::NONE];
        yield 'api' => ['api', MiddlewareTaxonomy::NONE];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('taxonomyCases')]
    public function testMiddlewareTaxonomy(string $middleware, string $expected): void
    {
        self::assertSame($expected, MiddlewareTaxonomy::classify($middleware));
    }

    public function testExtraMiddlewareCountsAsAuthorization(): void
    {
        self::assertSame(
            MiddlewareTaxonomy::AUTHORIZATION,
            MiddlewareTaxonomy::classify('myShield', ['myshield'])
        );
        self::assertSame(MiddlewareTaxonomy::GATE, MiddlewareTaxonomy::classify('myShield'));
    }
}
