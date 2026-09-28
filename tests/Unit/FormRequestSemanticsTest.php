<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Semantic\AuthorizationEvidence;
use Rampart\QualityChecker\Semantic\FormRequestIndex;
use Rampart\QualityChecker\Semantic\InlineValidation;
use Rampart\QualityChecker\Semantic\ValidationEvidence;

/**
 * v0.3.5 FormRequest semantics: rules presence/fields, authorize()
 * classification, inline validate()/validated() recognition.
 */
final class FormRequestSemanticsTest extends TestCase
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-fr-' . uniqid('', true);
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

    private function storeRequest(string $authorize, string $rules): string
    {
        return "<?php\nnamespace App\\Http\\Requests;\n" .
            "use Illuminate\\Foundation\\Http\\FormRequest;\n" .
            "class StoreUserRequest extends FormRequest {\n" .
            "    public function authorize() {\n        {$authorize}\n    }\n" .
            "    public function rules() {\n        {$rules}\n    }\n" .
            "}\n";
    }

    public function testExtractsLiteralRules(): void
    {
        $paths = $this->project([
            'app/Http/Requests/StoreUserRequest.php' => $this->storeRequest(
                'return true;',
                "return ['name' => 'required', 'email' => 'required|email'];"
            ),
        ]);
        $index = (new FormRequestIndex())->build($paths);
        $evidence = $index->validationEvidence('App\\Http\\Requests\\StoreUserRequest');

        self::assertInstanceOf(ValidationEvidence::class, $evidence);
        self::assertSame('form-request', $evidence->source);
        self::assertSame('App\\Http\\Requests\\StoreUserRequest', $evidence->requestClass);
        self::assertTrue($evidence->hasRules);
        self::assertSame(['name', 'email'], $evidence->fields);
        self::assertSame('high', $evidence->confidence);
    }

    public function testAuthorizeTrueIsNotAuthorization(): void
    {
        $paths = $this->project([
            'app/Http/Requests/StoreUserRequest.php' => $this->storeRequest(
                'return true;',
                "return ['name' => 'required'];"
            ),
        ]);
        $index = (new FormRequestIndex())->build($paths);

        // Validation yes (rules present), authorization no.
        self::assertInstanceOf(ValidationEvidence::class, $index->validationEvidence('App\\Http\\Requests\\StoreUserRequest'));
        self::assertNull($index->authorizationEvidence('App\\Http\\Requests\\StoreUserRequest'));
    }

    public function testAuthorizeCanIsStrongEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Requests/UpdatePostRequest.php' => "<?php\nnamespace App\\Http\\Requests;\n" .
                "use Illuminate\\Foundation\\Http\\FormRequest;\n" .
                "class UpdatePostRequest extends FormRequest {\n" .
                "    public function authorize() {\n" .
                "        return \$this->user()->can('update', \$this->post);\n" .
                "    }\n" .
                "    public function rules() {\n" .
                "        return ['title' => 'required'];\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = (new FormRequestIndex())->build($paths);
        $evidence = $index->authorizationEvidence('App\\Http\\Requests\\UpdatePostRequest');

        self::assertInstanceOf(AuthorizationEvidence::class, $evidence);
        self::assertSame('authorize-can', $evidence->mechanism);
        self::assertSame('update', $evidence->ability);
        self::assertSame('high', $evidence->confidence);
    }

    public function testAuthorizeGateIsStrongEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Requests/OpenAccountRequest.php' => "<?php\nnamespace App\\Http\\Requests;\n" .
                "use Illuminate\\Foundation\\Http\\FormRequest;\n" .
                "use Illuminate\\Support\\Facades\\Gate;\n" .
                "class OpenAccountRequest extends FormRequest {\n" .
                "    public function authorize() {\n" .
                "        return Gate::allows('open-account');\n" .
                "    }\n" .
                "    public function rules() {\n" .
                "        return ['name' => 'required'];\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = (new FormRequestIndex())->build($paths);
        $evidence = $index->authorizationEvidence('App\\Http\\Requests\\OpenAccountRequest');

        self::assertInstanceOf(AuthorizationEvidence::class, $evidence);
        self::assertSame('authorize-can', $evidence->mechanism);
        self::assertSame('open-account', $evidence->ability);
    }

    public function testAuthorizeCustomIsMediumEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Requests/CreateAccountRequest.php' => "<?php\nnamespace App\\Http\\Requests;\n" .
                "class CreateAccountRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {\n" .
                "    public function authorize() {\n" .
                "        return \\Ninja::isHosted();\n" .
                "    }\n" .
                "    public function rules() {\n" .
                "        return ['name' => 'required'];\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = (new FormRequestIndex())->build($paths);
        $evidence = $index->authorizationEvidence('App\\Http\\Requests\\CreateAccountRequest');

        self::assertInstanceOf(AuthorizationEvidence::class, $evidence);
        self::assertSame('authorize-custom', $evidence->mechanism);
        self::assertSame('medium', $evidence->confidence);
    }

    public function testDynamicRulesArePresenceWithoutFields(): void
    {
        $paths = $this->project([
            'app/Http/Requests/DynamicRequest.php' => "<?php\nnamespace App\\Http\\Requests;\n" .
                "use Illuminate\\Foundation\\Http\\FormRequest;\n" .
                "class DynamicRequest extends FormRequest {\n" .
                "    public function authorize() {\n" .
                "        return true;\n" .
                "    }\n" .
                "    public function rules() {\n" .
                "        return config('app.rules');\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = (new FormRequestIndex())->build($paths);
        $evidence = $index->validationEvidence('App\\Http\\Requests\\DynamicRequest');

        // Layer present, fields unknown — never false-safe.
        self::assertInstanceOf(ValidationEvidence::class, $evidence);
        self::assertTrue($evidence->hasRules);
        self::assertNull($evidence->fields);
        self::assertSame('medium', $evidence->confidence);
    }

    public function testMissingRulesIsNoEvidence(): void
    {
        $paths = $this->project([
            'app/Http/Requests/EmptyRequest.php' => "<?php\nnamespace App\\Http\\Requests;\n" .
                "use Illuminate\\Foundation\\Http\\FormRequest;\n" .
                "class EmptyRequest extends FormRequest {\n" .
                "    public function authorize() {\n" .
                "        return true;\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = (new FormRequestIndex())->build($paths);

        self::assertNull($index->validationEvidence('App\\Http\\Requests\\EmptyRequest'));
    }

    public function testUnresolvedClassIsNull(): void
    {
        $paths = $this->project([
            'app/Http/Requests/StoreUserRequest.php' => $this->storeRequest(
                'return true;',
                "return ['name' => 'required'];"
            ),
        ]);
        $index = (new FormRequestIndex())->build($paths);

        self::assertNull($index->validationEvidence('App\\Http\\Requests\\Missing'));
        self::assertNull($index->authorizationEvidence('App\\Http\\Requests\\Missing'));
    }

    /**
     * @return list<Node\Stmt\ClassMethod>
     */
    private function methodsOf(string $code): array
    {
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse("<?php\n" . $code);
        self::assertNotNull($ast);
        $finder = new \PhpParser\NodeFinder();
        $found = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod;
        });
        $out = [];
        foreach ($found as $method) {
            if ($method instanceof Node\Stmt\ClassMethod) {
                $out[] = $method;
            }
        }

        return $out;
    }

    public function testInlineValidateYieldsFields(): void
    {
        $methods = $this->methodsOf(
            "class C {\n" .
            "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
            "        \$request->validate(['name' => 'required', 'email' => 'email']);\n" .
            "    }\n" .
            "}\n"
        );
        $evidence = InlineValidation::recognize($methods[0]);

        self::assertNotEmpty($evidence);
        self::assertSame('inline-validate', $evidence[0]->source);
        self::assertSame(['name', 'email'], $evidence[0]->fields);
        self::assertSame('high', $evidence[0]->confidence);
    }

    public function testValidatedUseIsRecognized(): void
    {
        $methods = $this->methodsOf(
            "class C {\n" .
            "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
            "        return M::create(\$request->validated());\n" .
            "    }\n" .
            "}\n"
        );
        $evidence = InlineValidation::recognize($methods[0]);

        self::assertNotEmpty($evidence);
        $sources = array_column(array_map(static fn ($e) => $e->toArray(), $evidence), 'source');
        self::assertContains('validated-use', $sources);
    }

    public function testNoValidationRecognized(): void
    {
        $methods = $this->methodsOf(
            "class C {\n" .
            "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
            "        return M::create(\$request->all());\n" .
            "    }\n" .
            "}\n"
        );

        self::assertSame([], InlineValidation::recognize($methods[0]));
    }
}
