<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Security\AuthHardeningAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class AuthHardeningTest extends TestCase
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-auth-' . uniqid('', true);
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

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function onlyRule(array $issues, string $rule): array
    {
        return array_values(array_filter($issues, static fn (Issue $i): bool => $i->rule === $rule));
    }

    public function testSessionFixationFlagsAttemptWithoutRegenerate(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Auth;\nuse Illuminate\\Http\\Request;\n" .
            "class LoginController {\n    public function store(Request \$request) {\n" .
            "        if (Auth::attempt(\$request->only('email', 'password'))) {\n            return redirect('/home');\n        }\n" .
            "        return back();\n    }\n}\n",
            'app/Http/Controllers/LoginController.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'SESSION_FIXATION');

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'SESSION_FIXATION', Severity::Warning));
        self::assertStringContainsString('store', $issues[0]->message);
        self::assertSame('store', $issues[0]->metadata['function']);
    }

    public function testSessionFixationSilentWhenRegeneratePresent(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Auth;\nuse Illuminate\\Http\\Request;\n" .
            "class LoginController {\n    public function store(Request \$request) {\n" .
            "        if (Auth::attempt(\$request->only('email', 'password'))) {\n" .
            "            \$request->session()->regenerate();\n            return redirect('/home');\n        }\n" .
            "        return back();\n    }\n}\n",
            'app/Http/Controllers/LoginController.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'SESSION_FIXATION');

        self::assertCount(0, $issues);
    }

    public function testSessionFixationSilentWhenRegenerateInDifferentFunction(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Auth;\nuse Illuminate\\Http\\Request;\n" .
            "class LoginController {\n    public function store(Request \$request) {\n" .
            "        if (Auth::attempt(\$request->only('email', 'password'))) {\n            return redirect('/home');\n        }\n" .
            "        return back();\n    }\n" .
            "    public function refresh(Request \$request): void {\n        \$request->session()->regenerate();\n    }\n}\n",
            'app/Http/Controllers/LoginController.php'
        );

        // Regeneration in refresh() must not silence the login in store().
        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'SESSION_FIXATION');

        self::assertCount(1, $issues);
        self::assertSame('store', $issues[0]->metadata['function']);
    }

    public function testWeakPasswordPolicyFlagsShortPasswordMin(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Validation\\Rules\\Password;\n" .
            "class RegisterRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n" .
            "    public function rules(): array {\n        return ['password' => Password::min(4)];\n    }\n}\n",
            'app/Http/Requests/RegisterRequest.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'WEAK_PASSWORD_POLICY', Severity::Warning));
    }

    public function testWeakPasswordPolicyFlagsShortStringMinRule(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class RegisterController {\n    public function store(Request \$request): void {\n" .
            "        \$request->validate(['password' => 'required|min:6']);\n    }\n}\n",
            'app/Http/Controllers/RegisterController.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'WEAK_PASSWORD_POLICY', Severity::Warning));
    }

    public function testWeakPasswordPolicyFlagsMissingMinRule(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Requests;\n" .
            "class RegisterRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n" .
            "    public function rules(): array {\n        return ['password' => ['required', 'confirmed']];\n    }\n}\n",
            'app/Http/Requests/RegisterRequest.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertNotEmpty($issues);
        self::assertTrue($this->ruleMatches($issues[0], 'WEAK_PASSWORD_POLICY', Severity::Warning));
    }

    public function testWeakPasswordPolicySilentForSufficientMin(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class RegisterController {\n    public function store(Request \$request): void {\n" .
            "        \$request->validate(['password' => 'required|min:8']);\n    }\n}\n",
            'app/Http/Controllers/RegisterController.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertCount(0, $issues);
    }

    public function testWeakPasswordPolicySilentForNonPasswordMin(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\n" .
            "class RegisterController {\n    public function store(Request \$request): void {\n" .
            "        \$request->validate(['name' => 'required|min:4']);\n    }\n}\n",
            'app/Http/Controllers/RegisterController.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertCount(0, $issues);
    }

    public function testWeakPasswordPolicySilentForStrongPasswordMin(): void
    {
        $file = $this->tempPhp(
            "<?php\nnamespace App\\Http\\Requests;\nuse Illuminate\\Validation\\Rules\\Password;\n" .
            "class RegisterRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n" .
            "    public function rules(): array {\n        return ['password' => Password::min(12)];\n    }\n}\n",
            'app/Http/Requests/RegisterRequest.php'
        );

        $issues = $this->onlyRule((new AuthHardeningAnalyzer())->analyze([$file]), 'WEAK_PASSWORD_POLICY');

        self::assertCount(0, $issues);
    }
}
