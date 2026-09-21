<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Security\DisabledCsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\LaravelTaintAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\MassAssignmentAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\SqlInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\UnsafeDeserializationAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\UnsafeEvalAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class SecurityAnalyzersTest extends TestCase
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

    private function tempPhp(string $content, string $relPath = 'file.php'): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sec-' . uniqid('', true);
        $path = $dir . DIRECTORY_SEPARATOR . $relPath;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);
        $this->tempFiles[] = $path;

        return $path;
    }

    private function ruleMatches(Issue $issue, string $rule, Severity $severity): bool
    {
        return $issue->rule === $rule && $issue->severity === $severity;
    }

    /** SqlInjectionAnalyzer */

    public function testSqlInjectionFlagsConcatWithRequestInput(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class UserController {\n    public function index(Request \$request) {\n        return DB::select(\"select * from users where id = \" . \$request->input('id'));\n    }\n}\n",
            'app/Http/Controllers/UserController.php'
        );

        $issues = (new SqlInjectionAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'SQL_INJECTION', Severity::Critical));
    }

    public function testSqlInjectionFlagsWhereRawWithTaintedInput(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class ProductController {\n    public function index(Request \$request) {\n        return DB::table('products')->whereRaw('price > ' . \$request->input('min'))->get();\n    }\n}\n",
            'app/Http/Controllers/ProductController.php'
        );

        $issues = (new SqlInjectionAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertSame('SQL_INJECTION', $issues[0]->rule);
        self::assertSame(Severity::Critical, $issues[0]->severity);
    }

    public function testSqlInjectionSkipsParameterizedQuery(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class UserController {\n    public function index(Request \$request) {\n        return DB::table('users')->where('active', '=', true)->where('id', '=', \$request->input('id'))->get();\n    }\n}\n",
            'app/Http/Controllers/UserController.php'
        );

        $issues = (new SqlInjectionAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** UnsafeEvalAnalyzer */

    public function testUnsafeEvalFlagsRequestInput(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nuse Illuminate\\Http\\Request;\n" .
            "class EvalService {\n    public function run(Request \$request): void {\n        eval(\$request->input('code'));\n    }\n}\n",
            'app/Services/EvalService.php'
        );

        $issues = (new UnsafeEvalAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'UNSAFE_EVAL', Severity::Critical));
    }

    public function testUnsafeEvalSkipsLiteral(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass MathService {\n    public function calc(): int {\n        eval('return 1 + 1;');\n        return 2;\n    }\n}\n",
            'app/Services/MathService.php'
        );

        $issues = (new UnsafeEvalAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** HardcodedSecretAnalyzer */

    public function testHardcodedSecretFlagsOpenAiKey(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass ApiService {\n    private string \$key = 'sk-ABC12345678901234567890';\n}\n",
            'app/Services/ApiService.php'
        );

        $issues = (new HardcodedSecretAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'HARDCODED_SECRET', Severity::Critical));
    }

    public function testHardcodedSecretSkipsNormalVariable(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass GreetingService {\n    private string \$greeting = 'Hello World';\n}\n",
            'app/Services/GreetingService.php'
        );

        $issues = (new HardcodedSecretAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** MassAssignmentAnalyzer */

    public function testMassAssignmentFlagsUnprotectedModel(): void
    {
        $controller = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );
        $model = $this->tempPhp(
            "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            'app/Models/Order.php'
        );

        $issues = (new MassAssignmentAnalyzer())->analyze([$controller, $model]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'MASS_ASSIGNMENT', Severity::Error));
    }

    public function testMassAssignmentSkipsModelWithFillable(): void
    {
        $controller = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );
        $model = $this->tempPhp(
            "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {\n    protected \$fillable = ['name', 'email'];\n}\n",
            'app/Models/Order.php'
        );

        $issues = (new MassAssignmentAnalyzer())->analyze([$controller, $model]);

        self::assertCount(0, $issues);
    }

    public function testMassAssignmentSkipsGuardedModel(): void
    {
        $controller = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\n" .
            "class OrderController {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
            'app/Http/Controllers/OrderController.php'
        );
        $model = $this->tempPhp(
            "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {\n    protected \$guarded = [];\n}\n",
            'app/Models/Order.php'
        );

        $issues = (new MassAssignmentAnalyzer())->analyze([$controller, $model]);

        self::assertCount(0, $issues);
    }

    /** UnsafeDeserializationAnalyzer */

    public function testUnsafeDeserializationFlagsNonLiteral(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nuse Illuminate\\Http\\Request;\n" .
            "class SessionService {\n    public function hydrate(Request \$request): void {\n        \$payload = unserialize(\$request->input('data'));\n    }\n}\n",
            'app/Services/SessionService.php'
        );

        $issues = (new UnsafeDeserializationAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'UNSAFE_UNSERIALIZE', Severity::Critical));
    }

    public function testUnsafeDeserializationSkipsLiteral(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass CacheService {\n    public function hydrate(): array {\n        return unserialize('a:1:{s:1:\"a\";i:1;}');\n    }\n}\n",
            'app/Services/CacheService.php'
        );

        $issues = (new UnsafeDeserializationAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** InsecureHashAnalyzer */

    public function testInsecureHashFlagsPasswordContext(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass AuthService {\n    public function verify(string \$password): bool {\n        return md5(\$password) === \$this->storedHash;\n    }\n}\n",
            'app/Services/AuthService.php'
        );

        $issues = (new InsecureHashAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'INSECURE_HASH', Severity::Warning));
    }

    public function testInsecureHashSkipsNonCredentialContext(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Services;\nclass CacheService {\n    public function fingerprint(string \$payload): string {\n        return md5(\$payload);\n    }\n}\n",
            'app/Services/CacheService.php'
        );

        $issues = (new InsecureHashAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** LaravelTaintAnalyzer */

    public function testLaravelTaintFlagsWhereRawInterpolation(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nuse Illuminate\\Http\\Request;\n" .
            "class ProductController {\n    public function index(Request \$request) {\n        return DB::table('products')->whereRaw('price > ' . \$request->input('min'))->get();\n    }\n}\n",
            'app/Http/Controllers/ProductController.php'
        );

        $issues = (new LaravelTaintAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'LARAVEL_TAINT', Severity::Error));
    }

    public function testLaravelTaintSkipsLiteralWhereRaw(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\n" .
            "class ReportController {\n    public function index() {\n        return DB::table('orders')->whereRaw('count(*) as c')->get();\n    }\n}\n",
            'app/Http/Controllers/ReportController.php'
        );

        $issues = (new LaravelTaintAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    /** DisabledCsrfAnalyzer */

    public function testDisabledCsrfFlagsAuthorizeTrue(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Requests;\nclass UpdateUserRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n    public function authorize(): bool {\n        return true;\n    }\n}\n",
            'app/Http/Requests/UpdateUserRequest.php'
        );

        $issues = (new DisabledCsrfAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'DISABLED_CSRF_AUTHORIZE_TRUE', Severity::Warning));
    }

    public function testDisabledCsrfFlagsWildcardException(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Middleware;\nclass VerifyCsrfToken {\n    protected \$except = ['*'];\n}\n",
            'app/Http/Middleware/VerifyCsrfToken.php'
        );

        $issues = (new DisabledCsrfAnalyzer())->analyze([$file]);

        self::assertNotEmpty($issues);
        self::assertSame('DISABLED_CSRF_EXCEPTION_STAR', $issues[0]->rule);
        self::assertSame(Severity::Critical, $issues[0]->severity);
    }

    public function testDisabledCsrfSkipsSafeAuthorize(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Requests;\nclass UpdateUserRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n    public function authorize(): bool {\n        return \\Auth::user()->isAdmin();\n    }\n}\n",
            'app/Http/Requests/UpdateUserRequest.php'
        );

        $issues = (new DisabledCsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testDisabledCsrfSkipsScopedException(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Middleware;\nclass VerifyCsrfToken {\n    protected \$except = ['webhook/payment'];\n}\n",
            'app/Http/Middleware/VerifyCsrfToken.php'
        );

        $issues = (new DisabledCsrfAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }
}
