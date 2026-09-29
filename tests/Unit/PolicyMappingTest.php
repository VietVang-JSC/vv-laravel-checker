<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use Rampart\QualityChecker\Semantic\ModelTypeResolver;
use Rampart\QualityChecker\Semantic\PolicyRegistry;

/**
 * v0.3.6 Policy/Gate semantic mapping: registration resolution,
 * model types, ability → policy::method chains. Convention alone
 * never maps; unresolved chains stay medium, never guesses.
 */
final class PolicyMappingTest extends TestCase
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-pol-' . uniqid('', true);
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

    private function authProvider(): string
    {
        return "<?php\nnamespace App\\Providers;\n" .
            "use App\\Models\\Post;\nuse App\\Policies\\PostPolicy;\n" .
            "use Illuminate\\Support\\Facades\\Gate;\n" .
            "class AuthServiceProvider {\n" .
            "    protected \$policies = [\n" .
            "        Post::class => PostPolicy::class,\n" .
            "    ];\n" .
            "    public function boot() {\n" .
            "        Gate::define('edit-settings', function (\$user) {\n" .
            "            return \$user->is_admin;\n" .
            "        });\n" .
            "    }\n" .
            "}\n";
    }

    private function postPolicy(): string
    {
        return "<?php\nnamespace App\\Policies;\nuse App\\Models\\Post;\nuse App\\Models\\User;\n" .
            "class PostPolicy {\n" .
            "    public function update(User \$user, Post \$post) {\n" .
            "        return \$user->id === \$post->user_id;\n" .
            "    }\n" .
            "    public function viewAny(User \$user) {\n" .
            "        return true;\n" .
            "    }\n" .
            "}\n";
    }

    public function testResolvesPoliciesProperty(): void
    {
        $paths = $this->project(['app/Providers/AuthServiceProvider.php' => $this->authProvider()]);
        $registry = (new PolicyRegistry())->build($paths);

        $entry = $registry->policyForModel('App\\Models\\Post');
        self::assertNotNull($entry);
        self::assertSame('App\\Policies\\PostPolicy', $entry['policy']);
    }

    public function testResolvesGatePolicyCall(): void
    {
        $paths = $this->project([
            'app/Providers/AuthServiceProvider.php' => "<?php\nnamespace App\\Providers;\n" .
                "use App\\Models\\Comment;\nuse App\\Policies\\CommentPolicy;\n" .
                "use Illuminate\\Support\\Facades\\Gate;\n" .
                "class AuthServiceProvider {\n" .
                "    public function boot() {\n" .
                "        Gate::policy(Comment::class, CommentPolicy::class);\n" .
                "    }\n" .
                "}\n",
        ]);
        $registry = (new PolicyRegistry())->build($paths);

        self::assertSame(
            'App\\Policies\\CommentPolicy',
            $registry->policyForModel('App\\Models\\Comment')['policy'] ?? null
        );
    }

    public function testResolvesGateDefine(): void
    {
        $paths = $this->project(['app/Providers/AuthServiceProvider.php' => $this->authProvider()]);
        $registry = (new PolicyRegistry())->build($paths);

        $define = $registry->defineForAbility('edit-settings');
        self::assertNotNull($define);
        self::assertFalse($define['trivial']);
        self::assertNull($registry->defineForAbility('missing'));
    }

    public function testTrivialDefineIsMarked(): void
    {
        $paths = $this->project([
            'app/Providers/AuthServiceProvider.php' => "<?php\nnamespace App\\Providers;\n" .
                "use Illuminate\\Support\\Facades\\Gate;\n" .
                "class AuthServiceProvider {\n" .
                "    public function boot() {\n" .
                "        Gate::define('open', fn () => true);\n" .
                "    }\n" .
                "}\n",
        ]);
        $registry = (new PolicyRegistry())->build($paths);

        self::assertTrue($registry->defineForAbility('open')['trivial'] ?? false);
    }

    public function testNoConventionMapping(): void
    {
        // PostPolicy.php exists on disk but nothing registers it:
        // Post → PostPolicy must NOT resolve by name.
        $paths = $this->project([
            'app/Policies/PostPolicy.php' => $this->postPolicy(),
        ]);
        $registry = (new PolicyRegistry())->build($paths);

        self::assertNull($registry->policyForModel('App\\Models\\Post'));
        self::assertSame(
            'unresolved',
            $registry->resolveAuthorizeCall('update', 'App\\Models\\Post')['status']
        );
    }

    public function testFullChainResolves(): void
    {
        $paths = $this->project([
            'app/Providers/AuthServiceProvider.php' => $this->authProvider(),
            'app/Policies/PostPolicy.php' => $this->postPolicy(),
        ]);
        $registry = (new PolicyRegistry())->build($paths);

        $chain = $registry->policyChain('update', 'App\\Models\\Post');
        self::assertNotNull($chain);
        self::assertSame('App\\Policies\\PostPolicy', $chain['policy']);
        self::assertSame('update', $chain['method']);
        self::assertStringContainsString('PostPolicy.php', $chain['source']);

        $call = $registry->resolveAuthorizeCall('update', 'App\\Models\\Post');
        self::assertSame('resolved', $call['status']);
        self::assertSame('high', $call['confidence']);
    }

    public function testMissingPolicyMethodIsUnresolved(): void
    {
        $paths = $this->project([
            'app/Providers/AuthServiceProvider.php' => $this->authProvider(),
            'app/Policies/PostPolicy.php' => $this->postPolicy(),
        ]);
        $registry = (new PolicyRegistry())->build($paths);

        self::assertNull($registry->policyChain('publish', 'App\\Models\\Post'));
        $call = $registry->resolveAuthorizeCall('publish', 'App\\Models\\Post');
        self::assertSame('unresolved', $call['status']);
        self::assertSame('medium', $call['confidence']);
    }

    public function testAbilityOnlyDefine(): void
    {
        $paths = $this->project(['app/Providers/AuthServiceProvider.php' => $this->authProvider()]);
        $registry = (new PolicyRegistry())->build($paths);

        $call = $registry->resolveAuthorizeCall('edit-settings', null);
        self::assertSame('ability-only', $call['status']);
        self::assertSame('medium', $call['confidence']);
    }

    public function testDynamicAbilityIsUnresolved(): void
    {
        $paths = $this->project(['app/Providers/AuthServiceProvider.php' => $this->authProvider()]);
        $registry = (new PolicyRegistry())->build($paths);

        $call = $registry->resolveAuthorizeCall(null, 'App\\Models\\Post');
        self::assertSame('unresolved', $call['status']);
    }

    /**
     * @return list<Node\Stmt\ClassMethod>
     */
    private function methodsOf(string $code): array
    {
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse("<?php\n" . $code);
        self::assertNotNull($ast);
        $finder = new \PhpParser\NodeFinder();
        $out = [];
        foreach (
            $finder->find($ast, static function (Node $node): bool {
                return $node instanceof Node\Stmt\ClassMethod;
            }) as $method
        ) {
            if ($method instanceof Node\Stmt\ClassMethod) {
                $out[] = $method;
            }
        }

        return $out;
    }

    public function testModelTypeFromParam(): void
    {
        $methods = $this->methodsOf(
            "use App\\Models\\Post;\n" .
            "class C {\n" .
            "    public function update(\\Illuminate\\Http\\Request \$r, Post \$post) {}\n" .
            "}\n"
        );

        self::assertSame(
            'App\\Models\\Post',
            ModelTypeResolver::resolve(
                new Node\Expr\Variable('post'),
                $methods[0],
                ['post' => 'App\\Models\\Post'],
                null,
                10
            )
        );
    }

    public function testModelTypeFromAssign(): void
    {
        $methods = $this->methodsOf(
            "use App\\Models\\Post;\n" .
            "class C {\n" .
            "    public function update(\$id) {\n" .
            "        \$post = Post::findOrFail(\$id);\n" .
            "        \$x = 1;\n" .
            "    }\n" .
            "}\n"
        );

        self::assertSame(
            'App\\Models\\Post',
            ModelTypeResolver::resolve(
                new Node\Expr\Variable('post'),
                $methods[0],
                ['post' => 'App\\Models\\Post'],
                null,
                10
            )
        );
    }

    public function testModelTypeRepeatedAssignIsNull(): void
    {
        $methods = $this->methodsOf(
            "use App\\Models\\Post;\n" .
            "class C {\n" .
            "    public function update(\$id) {\n" .
            "        \$post = Post::find(\$id);\n" .
            "        \$post = Other::find(\$id);\n" .
            "        \$x = \$post->id;\n" .
            "    }\n" .
            "}\n"
        );

        self::assertNull(ModelTypeResolver::resolve(
            new Node\Expr\Variable('post'),
            $methods[0],
            [],
            null,
            10
        ));
    }

    public function testModelTypeLaterReassignDoesNotPoison(): void
    {
        // Flow-sensitive: only assignments preceding the use count; a
        // later reassignment cannot affect it.
        $methods = $this->methodsOf(
            "use App\\Models\\Post;\n" .
            "class C {\n" .
            "    public function update(\$id) {\n" .
            "        \$post = new Post;\n" .
            "        \$x = \$post->id;\n" .
            "        \$post = Other::find(\$id);\n" .
            "    }\n" .
            "}\n"
        );

        self::assertSame(
            'App\\Models\\Post',
            ModelTypeResolver::resolve(
                new Node\Expr\Variable('post'),
                $methods[0],
                ['post' => 'App\\Models\\Post'],
                null,
                6
            )
        );
    }

    public function testModelTypePropertyIsNull(): void
    {
        $methods = $this->methodsOf(
            "class C {\n" .
            "    public function update() {}\n" .
            "}\n"
        );

        self::assertNull(ModelTypeResolver::resolve(
            new Node\Expr\PropertyFetch(new Node\Expr\Variable('this'), 'post'),
            $methods[0],
            [],
            null,
            10
        ));
    }

    private function postController(string $body): string
    {
        return "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\n" .
            "class PostController extends Controller {\n" .
            "    public function update(\\Illuminate\\Http\\Request \$request, Post \$post) {\n" .
            "        {$body}\n" .
            "        \$post->save();\n" .
            "    }\n" .
            "}\n";
    }

    public function testProjectAResolvedChainSuppresses(): void
    {
        // Same Controller@update + $this->authorize('update', $post),
        // Post → PostPolicy::update registered → resolved/high.
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => $this->postController(
                "\$this->authorize('update', \$post);"
            ),
            'app/Providers/AuthServiceProvider.php' => $this->authProvider(),
            'app/Policies/PostPolicy.php' => $this->postPolicy(),
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame([], array_map(static fn ($i) => $i->rule, $issues));

        // And the registry proves the full chain independently.
        $registry = (new PolicyRegistry())->build($paths);
        $call = $registry->resolveAuthorizeCall('update', 'App\\Models\\Post');
        self::assertSame('resolved', $call['status']);
        self::assertSame('App\\Policies\\PostPolicy', $call['policy']);
        self::assertSame('update', $call['method']);
    }

    public function testProjectBUnresolvedMappingSuppressesMedium(): void
    {
        // Same call, mapping dynamic/unresolved: evidence exists but the
        // chain is unproven. The call is fail-closed (framework throws),
        // so it still suppresses — with medium, never high.
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => $this->postController(
                "\$this->authorize('update', \$post);"
            ),
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame([], array_map(static fn ($i) => $i->rule, $issues));

        $registry = (new PolicyRegistry())->build($paths);
        $call = $registry->resolveAuthorizeCall('update', 'App\\Models\\Post');
        self::assertSame('unresolved', $call['status']);
        self::assertSame('medium', $call['confidence']);
    }

    public function testProjectCNoCallFlags(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => $this->postController(''),
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame(['OWASP_BROKEN_ACCESS_CONTROL'], array_map(static fn ($i) => $i->rule, $issues));
    }

    public function testUnregisteredPolicyNameNeverMaps(): void
    {
        // PostPolicy exists with update(), but nothing registers it:
        // the analyzer must still suppress (fail-closed call), while the
        // registry refuses to prove the chain.
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => $this->postController(
                "\$this->authorize('update', \$post);"
            ),
            'app/Policies/PostPolicy.php' => $this->postPolicy(),
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame([], array_map(static fn ($i) => $i->rule, $issues));
        $registry = (new PolicyRegistry())->build($paths);
        self::assertSame(
            'unresolved',
            $registry->resolveAuthorizeCall('update', 'App\\Models\\Post')['status']
        );
    }

    public function testGateDeniesEnforcingSuppresses(): void
    {
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\n" .
                "use Illuminate\\Support\\Facades\\Gate;\n" .
                "class PostController extends Controller {\n" .
                "    public function update(\\Illuminate\\Http\\Request \$request, Post \$post) {\n" .
                "        if (Gate::denies('update', \$post)) {\n" .
                "            abort(403);\n" .
                "        }\n" .
                "        \$post->save();\n" .
                "    }\n" .
                "}\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame([], array_map(static fn ($i) => $i->rule, $issues));
    }

    public function testGateAllowsWithoutEnforcementFlags(): void
    {
        // Polarity: a bare allows() that only logs enforces nothing.
        $paths = $this->project([
            'app/Http/Controllers/PostController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\n" .
                "use Illuminate\\Support\\Facades\\Gate;\n" .
                "class PostController extends Controller {\n" .
                "    public function update(\\Illuminate\\Http\\Request \$request, Post \$post) {\n" .
                "        if (Gate::allows('update', \$post)) {\n" .
                "            \$logger->info('allowed');\n" .
                "        }\n" .
                "        \$post->save();\n" .
                "    }\n" .
                "}\n",
        ]);

        $issues = (new OwaspAccessControlAnalyzer())->analyze($paths);

        self::assertSame(['OWASP_BROKEN_ACCESS_CONTROL'], array_map(static fn ($i) => $i->rule, $issues));
    }
}
