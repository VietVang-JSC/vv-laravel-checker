<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Semantic\MiddlewareEvidence;
use Rampart\QualityChecker\Semantic\MiddlewareInspector;
use Rampart\QualityChecker\Semantic\MiddlewareRegistry;

/**
 * v0.3.3 tier 1 + tier 2: alias → class → handle() evidence.
 */
final class MiddlewareResolutionTest extends TestCase
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-mwres-' . uniqid('', true);
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

    private function kernel(): string
    {
        return "<?php\nnamespace App\\Http;\n" .
            "use App\\Http\\Middleware\\CheckPermissions;\n" .
            "use Illuminate\\Foundation\\Http\\Kernel as HttpKernel;\n" .
            "class Kernel extends HttpKernel {\n" .
            "    protected \$routeMiddleware = [\n" .
            "        'auth' => \\App\\Http\\Middleware\\Authenticate::class,\n" .
            "        'authorize' => CheckPermissions::class,\n" .
            "        'admin' => \\App\\Http\\Middleware\\admin::class,\n" .
            "        'link-id' => 'App\\\\Http\\\\Middleware\\\\LinkId',\n" .
            "    ];\n" .
            "}\n";
    }

    public function testResolvesKernelAliases(): void
    {
        $paths = $this->project(['app/Http/Kernel.php' => $this->kernel()]);
        $registry = (new MiddlewareRegistry())->build($paths);

        self::assertSame('App\\Http\\Middleware\\CheckPermissions', $registry->resolve('authorize')['class'] ?? null);
        self::assertSame('App\\Http\\Middleware\\admin', $registry->resolve('admin')['class'] ?? null);
        self::assertSame('App\\Http\\Middleware\\LinkId', $registry->resolve('link-id')['class'] ?? null);
        // Lookup is by base name: route parameters do not leak in.
        self::assertSame('App\\Http\\Middleware\\CheckPermissions', $registry->resolve('authorize:superuser')['class'] ?? null);
        self::assertNull($registry->resolve('missing'));
    }

    public function testResolvesAppBootstrapAliasCalls(): void
    {
        $paths = $this->project([
            'bootstrap/app.php' => "<?php\nuse App\\Http\\Middleware\\EnsureAdmin;\n" .
                "return Application::configure()->withMiddleware(function (Middleware \$middleware) {\n" .
                "    \$middleware->alias(['admin' => EnsureAdmin::class]);\n" .
                "})->create();\n",
        ]);
        $registry = (new MiddlewareRegistry())->build($paths);

        self::assertSame('App\\Http\\Middleware\\EnsureAdmin', $registry->resolve('admin')['class'] ?? null);
    }

    public function testClassFilePrefersMiddlewareDirectory(): void
    {
        $paths = $this->project([
            'app/Http/Kernel.php' => $this->kernel(),
            'app/Http/Middleware/admin.php' => "<?php\nnamespace App\\Http\\Middleware;\nclass admin {}\n",
            'app/Support/admin.php' => "<?php\nnamespace App\\Support;\nclass admin {}\n",
        ]);
        $registry = (new MiddlewareRegistry())->build($paths);

        $found = $registry->classFile('App\\Http\\Middleware\\admin');
        self::assertNotNull($found);
        self::assertStringContainsString('Middleware', (string) $found);
    }

    private function gateMiddleware(): string
    {
        return "<?php\nnamespace App\\Http\\Middleware;\n" .
            "use Closure;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n" .
            "class CheckPermissions {\n" .
            "    public function handle(Request \$request, Closure \$next, \$section = null) {\n" .
            "        if (Gate::allows(\$section)) {\n" .
            "            return \$next(\$request);\n" .
            "        }\n" .
            "        return response()->view('layouts/basic', ['content' => view('errors/403')], 403);\n" .
            "    }\n" .
            "}\n";
    }

    private function roleRedirectMiddleware(): string
    {
        return "<?php\nnamespace App\\Http\\Middleware;\n" .
            "use Auth;\nuse Closure;\nuse Illuminate\\Http\\Request;\n" .
            "class admin {\n" .
            "    public function handle(Request \$request, Closure \$next) {\n" .
            "        if (Auth::user() && Auth::user()->role == 'admin') {\n" .
            "            return \$next(\$request);\n" .
            "        }\n" .
            "        return redirect(url('dashboard'));\n" .
            "    }\n" .
            "}\n";
    }

    public function testInspectsGateAllowsWith403(): void
    {
        $paths = $this->project(['app/Http/Middleware/CheckPermissions.php' => $this->gateMiddleware()]);
        $evidence = (new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\CheckPermissions',
            'authorize',
            'superuser'
        );

        self::assertInstanceOf(MiddlewareEvidence::class, $evidence);
        self::assertSame('middleware', $evidence->type);
        self::assertSame('authorize', $evidence->alias);
        self::assertSame('App\\Http\\Middleware\\CheckPermissions', $evidence->class);
        self::assertSame('handle', $evidence->method);
        self::assertSame('gate', $evidence->mechanism);
        self::assertSame('superuser', $evidence->ability);
        self::assertSame('high', $evidence->confidence);
        self::assertStringContainsString('CheckPermissions.php:', $evidence->source);
    }

    public function testInspectsRoleGuardWithRedirectAsMedium(): void
    {
        $paths = $this->project(['app/Http/Middleware/admin.php' => $this->roleRedirectMiddleware()]);
        $evidence = (new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\admin',
            'admin'
        );

        self::assertInstanceOf(MiddlewareEvidence::class, $evidence);
        self::assertSame('role', $evidence->mechanism);
        self::assertSame('admin', $evidence->ability);
        // Redirect fallback: a gate, but weaker than a 403.
        self::assertSame('medium', $evidence->confidence);
    }

    public function testInspectsRoleGuardWithAbortAsHigh(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/EnsureAdmin.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\n" .
                "class EnsureAdmin {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        abort_unless(\$request->user()->role === 'admin', 403);\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);
        $evidence = (new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\EnsureAdmin',
            'admin'
        );

        self::assertInstanceOf(MiddlewareEvidence::class, $evidence);
        self::assertSame('role', $evidence->mechanism);
        self::assertSame('high', $evidence->confidence);
    }

    public function testIgnoresOwnershipChecks(): void
    {
        // Object-level authorization is a later phase: must stay null.
        $paths = $this->project([
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
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\LinkId',
            'link-id'
        ));
    }

    public function testIgnoresRedirectOnlyMiddleware(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/RedirectIfAuthenticated.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\n" .
                "class RedirectIfAuthenticated {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        if (\\Auth::check()) {\n" .
                "            return redirect('/dashboard');\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\RedirectIfAuthenticated',
            'guest'
        ));
    }

    public function testIgnoresTruthyFlagWithoutLiteral(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/CheckBlockedUser.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\n" .
                "class CheckBlockedUser {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        if (\\Auth::user()->blocked) {\n" .
                "            return abort(403);\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\CheckBlockedUser',
            'blocked'
        ));
    }

    public function testBareGateAuthorizeIsSelfEnforcing(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/CanDo.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n" .
                "class CanDo {\n" .
                "    public function handle(Request \$request, Closure \$next, string \$ability) {\n" .
                "        Gate::authorize(\$ability);\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);
        $evidence = (new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\CanDo',
            'cando',
            'reports.view'
        );

        self::assertInstanceOf(MiddlewareEvidence::class, $evidence);
        self::assertSame('gate', $evidence->mechanism);
        self::assertSame('reports.view', $evidence->ability);
    }

    public function testBareAllowsWithoutEnforcementIsNull(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/SoftCheck.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n" .
                "class SoftCheck {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        Gate::allows('view');\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\SoftCheck',
            'soft'
        ));
    }

    public function testMissingHandleIsNull(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/Empty.php' => "<?php\nnamespace App\\Http\\Middleware;\nclass Empty {}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\Empty',
            'empty'
        ));
    }

    public function testIgnoresTriggerNestedInUnrelatedCondition(): void
    {
        // Real-world shape (Linkstack CheckBlockedUser): the role check
        // is conjoined with a maintenance flag and $next is reachable
        // without it — it gates a branch, not the request.
        $paths = $this->project([
            'app/Http/Middleware/CheckBlockedUser.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Auth;\nuse Closure;\n" .
                "class CheckBlockedUser {\n" .
                "    public function handle(\$request, Closure \$next) {\n" .
                "        if (Auth::check() && Auth::user()->block === 'yes') {\n" .
                "            return redirect()->route('blocked');\n" .
                "        }\n" .
                "        if (env('MAINTENANCE_MODE') == 'true' && (Auth::check() && Auth::user()->role != 'admin')) {\n" .
                "            return redirect(url(''));\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\CheckBlockedUser',
            'blocked'
        ));
    }

    public function testIgnoresInvertedRoleCheck(): void
    {
        // Denies one value instead of authorizing the action.
        $paths = $this->project([
            'app/Http/Middleware/BanCheck.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\n" .
                "class BanCheck {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        if (\$request->user()->role == 'banned') {\n" .
                "            abort(403);\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);

        self::assertNull((new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\BanCheck',
            'ban'
        ));
    }

    public function testRecognizesDeniesShape(): void
    {
        $paths = $this->project([
            'app/Http/Middleware/EnsureAdmin.php' => "<?php\nnamespace App\\Http\\Middleware;\n" .
                "use Closure;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\Gate;\n" .
                "class EnsureAdmin {\n" .
                "    public function handle(Request \$request, Closure \$next) {\n" .
                "        if (Gate::denies('admin')) {\n" .
                "            abort(403);\n" .
                "        }\n" .
                "        return \$next(\$request);\n" .
                "    }\n" .
                "}\n",
        ]);
        $evidence = (new MiddlewareInspector())->inspect(
            $paths[0],
            'App\\Http\\Middleware\\EnsureAdmin',
            'admin'
        );

        self::assertInstanceOf(MiddlewareEvidence::class, $evidence);
        self::assertSame('gate', $evidence->mechanism);
        self::assertSame('admin', $evidence->ability);
        self::assertSame('high', $evidence->confidence);
    }
}
