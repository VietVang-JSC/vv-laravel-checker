<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\TestCoverage\TestCoverageAnalyzer;
use VietVang\QualityChecker\Result\Severity;

final class TestCoverageAnalyzerTest extends TestCase
{
    private function make(string $rel, string $content): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-tc-' . uniqid('', true);
        $path = $dir . DIRECTORY_SEPARATOR . $rel;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    private function controller(string $rel, string $ns, string $class): string
    {
        return $this->make($rel, "<?php\nnamespace $ns;\nclass $class extends \\Controller {\n    public function store() {}\n}\n");
    }

    private function service(string $rel, string $ns, string $class): string
    {
        return $this->make($rel, "<?php\nnamespace $ns;\nclass $class {\n    public function run() {}\n}\n");
    }

    private function test(string $rel, string $ns, string $class): string
    {
        return $this->make($rel, "<?php\nnamespace $ns;\nclass $class extends \\Tests\\TestCase {\n    public function testX(): void { \$this->assertTrue(true); }\n}\n");
    }

    public function testMissingControllerTestDetected(): void
    {
        $ctrl = $this->controller('app/Http/Controllers/UserController.php', 'App\Http\Controllers', 'UserController');
        $issues = (new TestCoverageAnalyzer())->analyze([$ctrl]);

        self::assertNotEmpty($issues);
        self::assertSame('MISSING_CONTROLLER_TEST', $issues[0]->rule);
        self::assertSame(Severity::Warning, $issues[0]->severity);
    }

    public function testControllerWithTestPasses(): void
    {
        $ctrl = $this->controller('app/Http/Controllers/UserController.php', 'App\Http\Controllers', 'UserController');
        $test = $this->test('tests/Feature/UserControllerTest.php', 'Tests\Feature', 'UserControllerTest');
        $issues = (new TestCoverageAnalyzer())->analyze([$ctrl, $test]);

        self::assertCount(0, $issues);
    }

    public function testMissingServiceTestDetected(): void
    {
        $svc = $this->service('app/Services/PaymentService.php', 'App\Services', 'PaymentService');
        $issues = (new TestCoverageAnalyzer())->analyze([$svc]);

        self::assertNotEmpty($issues);
        self::assertSame('MISSING_SERVICE_TEST', $issues[0]->rule);
    }

    public function testServiceWithUnitTestPasses(): void
    {
        $svc = $this->service('app/Services/PaymentService.php', 'App\Services', 'PaymentService');
        $test = $this->test('tests/Unit/PaymentServiceTest.php', 'Tests\Unit', 'PaymentServiceTest');
        $issues = (new TestCoverageAnalyzer())->analyze([$svc, $test]);

        self::assertCount(0, $issues);
    }

    public function testFlatTestLayoutDetected(): void
    {
        // Controller in App\Http\Controllers, test in Tests\Feature flat (no namespace mirror).
        $ctrl = $this->controller('app/Http/Controllers/OrderController.php', 'App\Http\Controllers', 'OrderController');
        $test = $this->test('tests/Feature/OrderControllerTest.php', 'Tests\Feature', 'OrderControllerTest');
        $issues = (new TestCoverageAnalyzer())->analyze([$ctrl, $test]);

        self::assertCount(0, $issues, 'Flat *Test.php layout should satisfy coverage.');
    }

    public function testSimpleModelSkipped(): void
    {
        // Model with few methods (no custom logic) should NOT be flagged.
        $model = $this->make('app/Models/Level.php', "<?php\nnamespace App\\Models;\nclass Level extends \\Illuminate\\Database\\Eloquent\\Model {}\n");
        $issues = (new TestCoverageAnalyzer())->analyze([$model]);

        self::assertCount(0, $issues);
    }

    public function testComplexModelWithNoTestDetected(): void
    {
        $model = $this->make(
            'app/Models/User.php',
            "<?php\nnamespace App\\Models;\nclass User extends \\Illuminate\\Database\\Eloquent\\Model {\n    public function scopeActive(\$q) { return \$q; }\n    public function getFullName() { return ''; }\n    public function isAdmin() { return true; }\n}\n"
        );
        $issues = (new TestCoverageAnalyzer())->analyze([$model]);

        self::assertNotEmpty($issues);
        self::assertSame('MISSING_MODEL_TEST', $issues[0]->rule);
    }

    public function testIgnoresTestFilesThemselves(): void
    {
        $test = $this->test('tests/Feature/FooTest.php', 'Tests\Feature', 'FooTest');
        $issues = (new TestCoverageAnalyzer())->analyze([$test]);

        self::assertCount(0, $issues);
    }
}
