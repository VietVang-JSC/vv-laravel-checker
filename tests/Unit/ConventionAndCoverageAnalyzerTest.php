<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Convention\DeadCodeAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\LaravelPitfallAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\NamingConventionAnalyzer;
use Rampart\QualityChecker\Analyzers\Convention\TodoFixmeAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\ControllerTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\FeatureTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\MissingTestAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\TestCoverageAnalyzer;
use Rampart\QualityChecker\Analyzers\TestCoverage\TestWithoutAssertAnalyzer;
use Rampart\QualityChecker\Scanning\ScanContext;
use Rampart\QualityChecker\Scanning\ScanContextAware;

/**
 * The convention and test-coverage analyzers had no direct test at all. That
 * was not obvious: the suite is green and the total count is high, but every one
 * of these was only ever exercised as a side effect of a checker run that had
 * them disabled by default, or not enabled at all.
 *
 * A green suite that never constructed the class cannot tell you the class
 * works, only that nothing else noticed it was broken. These cases pin the
 * behavior each one actually produces.
 */
final class ConventionAndCoverageAnalyzerTest extends TestCase
{
    private string $root = '';

    private string $caller = '';

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-conv-' . uniqid('', true);
        $this->caller = $this->root . DIRECTORY_SEPARATOR . 'caller';
        foreach (['app/Http/Controllers', 'app/Services', 'app/Models', 'routes', 'tests/Feature', 'config'] as $dir) {
            @mkdir($this->root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $dir), 0777, true);
        }
        @mkdir($this->caller . DIRECTORY_SEPARATOR . 'app', 0777, true);
        @mkdir($this->caller . DIRECTORY_SEPARATOR . 'routes', 0777, true);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        foreach ([$this->root] as $dir) {
            if ($dir === '' || !is_dir($dir)) {
                continue;
            }
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($dir);
        }
        $this->root = '';
        $this->caller = '';
        parent::tearDown();
    }

    private function write(string $relative, string $contents): string
    {
        $path = $this->root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * Run an analyzer the way the checker does: with a ScanContext that knows the
     * project root, which is how every path-resolving analyzer now locates
     * `routes/` and `tests/`.
     *
     * @param list<string> $files
     * @return list<string>
     */
    private function rules(object $analyzer, array $files): array
    {
        $scan = new ScanContext();
        $scan->setBasePath($this->root);
        if ($analyzer instanceof ScanContextAware) {
            $analyzer->setScanContext($scan);
        }

        return array_map(
            static fn ($issue): string => $issue->rule,
            $analyzer->analyze($files)
        );
    }

    public function testNamingConventionFlagsControllerAndBoolPrefix(): void
    {
        $file = $this->write(
            'app/Http/Controllers/UserHandler.php',
            "<?php\nnamespace App\\Http\\Controllers;\nclass UserHandler {\n    public function isActive(\$u) { return true; }\n}\n"
        );

        $issues = (new NamingConventionAnalyzer())->analyze([$file]);

        self::assertCount(2, $issues, 'Expected the class-suffix and the bool-prefix rule.');
        self::assertSame('NAMING_CONVENTION', $issues[0]->rule);
        self::assertStringContainsString('must end with "Controller"', $issues[0]->message);
        self::assertStringContainsString('should declare a bool return type', $issues[1]->message);
    }

    public function testNamingConventionIsSilentOnCorrectNames(): void
    {
        $file = $this->write(
            'app/Http/Controllers/UserController.php',
            "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function isActive(\$u): bool { return true; }\n}\n"
        );

        self::assertSame([], (new NamingConventionAnalyzer())->analyze([$file]));
    }

    public function testTodoFixmeFindsBothMarkers(): void
    {
        $file = $this->write(
            'app/Services/OrderProcessor.php',
            "<?php\nnamespace App\\Services;\nclass OrderProcessor {\n    public function run() {\n        // TODO: implement\n        // FIXME broken\n        return 1;\n    }\n}\n"
        );

        $issues = (new TodoFixmeAnalyzer())->analyze([$file]);

        self::assertCount(2, $issues);
        self::assertSame('TODO_FIXME', $issues[0]->rule);
        self::assertStringContainsString('TODO', $issues[0]->message);
        self::assertStringContainsString('FIXME', $issues[1]->message);
    }

    public function testLaravelPitfallFindsDebugEnvAndSleepInTest(): void
    {
        $app = $this->write(
            'app/Bad.php',
            "<?php\nnamespace App;\nclass Bad {\n    public function a(\$x) {\n        dd(\$x);\n        return env('APP_URL');\n    }\n}\n"
        );
        // env() is legitimate in config/ and a finding in application code.
        $this->write('config/app.php', "<?php\nreturn ['url' => env('APP_URL')];\n");
        $test = $this->write(
            'tests/ExampleTest.php',
            "<?php\nclass ExampleTest extends TestCase {\n    public function test_slow() { sleep(10); }\n}\n"
        );

        $issues = (new LaravelPitfallAnalyzer())->analyze([$app, $test]);
        $byRule = [];
        foreach ($issues as $issue) {
            $byRule[$issue->rule][] = basename((string) $issue->file);
        }

        self::assertArrayHasKey('LARAVEL_PITFALL_DEBUG', $byRule);
        self::assertArrayHasKey('LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG', $byRule);
        self::assertArrayHasKey('LARAVEL_PITFALL_SLEEP_IN_TEST', $byRule);
        self::assertSame(['Bad.php'], $byRule['LARAVEL_PITFALL_DEBUG']);
        self::assertSame(['Bad.php'], $byRule['LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG'], 'env() in config/ is not a finding.');
    }

    public function testTestWithoutAssertFindsAFactoryCallWithNoAssertion(): void
    {
        $file = $this->write(
            'tests/Feature/OrderTest.php',
            "<?php\nclass OrderTest extends TestCase {\n    public function test_no_assert() {\n        factory(Order::class)->create();\n    }\n}\n"
        );

        $issues = (new TestWithoutAssertAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame('TEST_WITHOUT_ASSERT', $issues[0]->rule);
    }

    /**
     * The regression this pins: both analyzers used to resolve `routes/` and
     * `tests/Feature/` against getcwd(). Pointed at another project — the normal
     * way this tool is used — they read the caller's directories and attributed
     * what they found to the target.
     */
    public function testAnalyzersResolveAgainstTheTargetNotTheWorkingDirectory(): void
    {
        $targetRoutes = $this->write(
            'routes/web.php',
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/orders', 'OrderController@store');\nRoute::get('/profile', 'ProfileController@show');\n"
        );
        $targetTest = $this->write(
            'tests/Feature/OrderTest.php',
            "<?php\nclass OrderTest extends TestCase { public function test_store() { \$this->postJson('/orders', []); } }\n"
        );
        $callerRoutes = $this->caller . DIRECTORY_SEPARATOR . 'routes'
            . DIRECTORY_SEPARATOR . 'web.php';
        file_put_contents(
            $callerRoutes,
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/caller-only-route', 'XController@y');\n"
        );

        $scan = new ScanContext();
        $scan->setBasePath($this->root);
        $analyzer = new FeatureTestAnalyzer();
        $analyzer->setScanContext($scan);

        $issues = $analyzer->analyze([$targetRoutes, $targetTest, $callerRoutes]);

        self::assertCount(1, $issues, 'Only the target\'s uncovered route should be reported.');
        self::assertStringContainsString('/profile', $issues[0]->message);
        foreach ($issues as $issue) {
            self::assertStringNotContainsString(
                'caller-only-route',
                $issue->message,
                'The caller project\'s routes leaked into the target\'s report.'
            );
        }
    }

    public function testFeatureCoverageIsSilentWhenEveryRouteIsCovered(): void
    {
        $routes = $this->write(
            'routes/web.php',
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/orders', 'OrderController@store');\n"
        );
        $test = $this->write(
            'tests/Feature/OrderTest.php',
            "<?php\nclass OrderTest extends TestCase { public function test_store() { \$this->postJson('/orders', []); } }\n"
        );

        self::assertSame([], $this->rules(new FeatureTestAnalyzer(), [$routes, $test]));
    }

    public function testControllerTestFindsAControllerWithNoTest(): void
    {
        $controller = $this->write(
            'app/Http/Controllers/InvoiceController.php',
            "<?php\nnamespace App\\Http\\Controllers;\nclass InvoiceController extends Controller {\n    public function store() { return 1; }\n}\n"
        );
        $this->write('tests/Feature/OtherTest.php', "<?php\nclass OtherTest extends TestCase { public function test_a() { \$this->assertTrue(true); } }\n");

        $scan = new ScanContext();
        $scan->setBasePath($this->root);
        $analyzer = new ControllerTestAnalyzer();
        $analyzer->setScanContext($scan);

        $rules = array_map(static fn ($i): string => $i->rule, $analyzer->analyze([$controller]));

        self::assertContains('MISSING_CONTROLLER_TEST', $rules);
    }

    public function testMissingTestFindsAnUntestedModel(): void
    {
        // Three methods: the analyzer treats a model with a real surface area as
        // worth a test. Fewer than that is a plain Eloquent shell, deliberately
        // skipped so the rule points at models that actually have logic.
        $model = $this->write(
            'app/Models/Invoice.php',
            "<?php\nnamespace App\\Models;\nclass Invoice extends Model {\n    public function total() { return 1; }\n    public function isPaid() { return true; }\n    public function markPaid() { return \$this; }\n}\n"
        );

        $rules = array_map(
            static fn ($i): string => $i->rule,
            (new MissingTestAnalyzer(['models']))->analyze([$model])
        );

        self::assertContains('MISSING_MODEL_TEST', $rules);
    }

    public function testMissingTestSkipsAModelWithNoCustomLogic(): void
    {
        $model = $this->write(
            'app/Models/Pivot.php',
            "<?php\nnamespace App\\Models;\nclass Pivot extends Model { public function id() { return 1; } }\n"
        );

        self::assertSame([], (new MissingTestAnalyzer(['models']))->analyze([$model]));
    }

    public function testUnifiedTestCoverageReportsAMissingFeatureTest(): void
    {
        $controller = $this->write(
            'app/Http/Controllers/InvoiceController.php',
            "<?php\nnamespace App\\Http\\Controllers;\nclass InvoiceController extends Controller {\n    public function store() { return 1; }\n}\n"
        );
        $this->write('tests/Feature/UnrelatedTest.php', "<?php\nclass UnrelatedTest extends TestCase { public function test_x() { \$this->assertTrue(true); } }\n");

        $scan = new ScanContext();
        $scan->setBasePath($this->root);
        $analyzer = new TestCoverageAnalyzer();
        $analyzer->setScanContext($scan);

        $rules = array_map(static fn ($i): string => $i->rule, $analyzer->analyze([$controller]));

        self::assertNotSame([], $rules, 'The unified detector produced nothing for an untested controller.');
    }

    public function testDeadCodeAnalyzerFindsAnUnusedPrivateMethod(): void
    {
        $file = $this->write(
            'app/Services/Legacy.php',
            "<?php\nnamespace App\\Services;\nclass Legacy {\n    public function run() { return 1; }\n    private function neverCalled() { return 2; }\n}\n"
        );

        $issues = (new DeadCodeAnalyzer())->analyze([$file]);
        $rules = array_map(static fn ($i): string => $i->rule, $issues);

        self::assertNotSame([], $rules, 'An unreferenced private method should be reported.');
    }
}
