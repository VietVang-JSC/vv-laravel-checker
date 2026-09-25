<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class OwaspOpenRedirectAnalyzerTest extends TestCase
{
    private function temp(string $content, string $relPath): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-openredirect-' . uniqid('', true);
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

    public function testFlagsRedirectWithRequestInput(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(\$request->input('next'));\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testFlagsRedirectAwayWithVariable(): void
    {
        $file = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Redirect;\nreturn Redirect::away(\$url);\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
        self::assertSame(Severity::Error, $issues[0]->severity ?? null);
    }

    public function testFlagsRedirectWithConcatTarget(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect('/go?next=' . \$next);\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
    }

    public function testFlagsRedirectToWithMethodCall(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect()->to(\$request->query('next'));\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsRedirectRoute(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect()->route('home');\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsFacadeRoute(): void
    {
        $file = $this->temp(
            "<?php\nuse Illuminate\\Support\\Facades\\Redirect;\nreturn Redirect::route('home');\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsBack(): void
    {
        $redirect = $this->temp(
            "<?php\nreturn redirect()->back();\n",
            'app/Http/Controllers/AuthController.php'
        );
        $helper = $this->temp(
            "<?php\nreturn back();\n",
            'app/Http/Controllers/ProfileController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$redirect, $helper]);

        self::assertCount(0, $issues);
    }

    public function testSkipsLiteralTarget(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect('/home');\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsConfigBasedTarget(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(config('app.url') . '/done');\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsUrlPreviousTarget(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(url()->previous());\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsUrlHelperWithLiteral(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect()->to(url('install/database'));\n",
            'app/Http/Controllers/InstallController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testFlagsUrlHelperWithDynamicArg(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(url(\$request->input('next')));\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsConfigAssignedVariable(): void
    {
        $file = $this->temp(
            "<?php\nnamespace App\\Http\\Controllers\\Admin;\nclass LoginCuserController extends Controller {\n" .
            "    public function corporate() {\n" .
            "        \$webALoginUrl = config('app.url_course') . '/login';\n" .
            "        return redirect()->away(\$webALoginUrl);\n" .
            "    }\n}\n",
            'app/Http/Controllers/Admin/LoginCuserController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsInputAssignedVariable(): void
    {
        $file = $this->temp(
            "<?php\nclass LoginController extends Controller {\n" .
            "    public function login() {\n" .
            "        \$next = \$request->input('next');\n" .
            "        return redirect(\$next);\n" .
            "    }\n}\n",
            'app/Http/Controllers/LoginController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
    }

    public function testVariableTargetIsHighConfidence(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(\$request->input('next'));\n",
            'app/Http/Controllers/AuthController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame(Confidence::High, $issues[0]->confidence ?? null);
    }

    public function testMethodCallTargetIsMediumConfidence(): void
    {
        $file = $this->temp(
            "<?php\nreturn redirect(\$page->getUrl());\n",
            'app/Entities/Controllers/PageController.php'
        );

        $issues = (new OwaspOpenRedirectAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_OPEN_REDIRECT', $this->rules($issues)[0] ?? null);
        self::assertSame(Confidence::Medium, $issues[0]->confidence ?? null);
    }
}
