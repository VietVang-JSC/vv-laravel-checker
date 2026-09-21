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
}
