<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analysis\ConstantScope;
use Rampart\QualityChecker\Analysis\ConstantValueResolver;

/**
 * v0.3.4 bounded constant propagation: resolve only what is proven,
 * otherwise null. False resolution is worse than unresolved.
 */
final class ConstantValueResolverTest extends TestCase
{
    /**
     * @return array{scope: ConstantScope, calls: list<Node\Expr\StaticCall|Node\Expr\MethodCall>}
     */
    private function scopeOf(string $code, string $file = 'routes/web.php'): array
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $ast = $parser->parse("<?php\n" . $code);
        self::assertNotNull($ast);
        $nodes = array_values($ast);
        $finder = new \PhpParser\NodeFinder();
        $calls = [];
        foreach (
            $finder->find($nodes, static function (Node $node): bool {
                return $node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall;
            }) as $call
        ) {
            if ($call instanceof Node\Expr\StaticCall || $call instanceof Node\Expr\MethodCall) {
                $calls[] = $call;
            }
        }

        return ['scope' => ConstantScope::forFile($nodes, $file), 'calls' => $calls];
    }

    private function resolveTarget(string $code, int $callIndex = 0, int $argIndex = 1): ?string
    {
        ['scope' => $scope, 'calls' => $calls] = $this->scopeOf($code);
        $call = $calls[$callIndex] ?? null;
        self::assertNotNull($call, 'route call not found in fixture');
        $arg = $call->args[$argIndex] ?? null;
        self::assertInstanceOf(Node\Arg::class, $arg);
        $resolver = new ConstantValueResolver();
        // Scope discipline: resolve in the use-site's own function scope.
        $useScope = $scope->forNode($call);
        $value = $resolver->resolve($arg->value, $useScope, $call->getStartLine());

        return $value?->value;
    }

    public function testResolvesStringLiteral(): void
    {
        self::assertSame(
            'App\\Http\\Controllers\\C@show',
            $this->resolveTarget("use Illuminate\\Support\\Facades\\Route;\nRoute::get('/x', 'App\\\\Http\\\\Controllers\\\\C@show');\n")
        );
    }

    public function testResolvesSingleAssignment(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$controller = 'App\\\\Http\\\\Controllers\\\\C@show';\n" .
            "Route::get('/x', \$controller);\n"
        );

        self::assertSame('App\\Http\\Controllers\\C@show', $value);
    }

    public function testResolvesAssignmentChain(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$base = 'App\\\\Http\\\\Controllers\\\\C';\n" .
            "\$controller = \$base . '@show';\n" .
            "Route::get('/x', \$controller);\n"
        );

        self::assertSame('App\\Http\\Controllers\\C@show', $value);
    }

    public function testResolvesConcatWithLiterals(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$prefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
            "Route::get('/x', \$prefix . 'C@show');\n"
        );

        self::assertSame('App\\Http\\Controllers\\C@show', $value);
    }

    public function testVoyagerNamespacePrefixShape(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$namespacePrefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
            "Route::get('/user', \$namespacePrefix . 'UserController@login');\n"
        );

        self::assertSame('App\\Http\\Controllers\\UserController@login', $value);
    }

    public function testClosureBodyAssignmentResolves(): void
    {
        // Registration callbacks run once, in order: assigns at the top
        // of the enclosing closure body are visible to uses inside it.
        // (Call index 1: index 0 is the outer Route::group call.)
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "Route::group(['prefix' => 'admin'], function () {\n" .
            "    \$prefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
            "    Route::get('/user', \$prefix . 'UserController@show');\n" .
            "});\n",
            1
        );

        self::assertSame('App\\Http\\Controllers\\UserController@show', $value);
    }

    public function testClosureNestedReassignmentIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "Route::group(['prefix' => 'admin'], function () {\n" .
            "    \$prefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
            "    if (\$condition) {\n" .
            "        \$prefix = 'Other\\\\';\n" .
            "    }\n" .
            "    Route::get('/user', \$prefix . 'UserController@show');\n" .
            "});\n",
            1
        );

        self::assertNull($value);
    }

    public function testResolvesClassConstFetch(): void
    {
        ['scope' => $scope, 'calls' => $calls] = $this->scopeOf(
            "use Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\C;\nRoute::get('/x', [C::class, 'show']);\n"
        );
        $arg = $calls[0]->args[1];
        self::assertInstanceOf(Node\Arg::class, $arg);
        self::assertInstanceOf(Node\Expr\Array_::class, $arg->value);
        $classItem = $arg->value->items[0];
        self::assertInstanceOf(Node\Expr\ArrayItem::class, $classItem);
        $value = (new ConstantValueResolver())->resolve($classItem->value, $scope, $calls[0]->getStartLine());

        self::assertSame('App\\Http\\Controllers\\C', $value?->value);
    }

    public function testResolvesDirMagic(): void
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $ast = $parser->parse("<?php\nrequire __DIR__ . '/admin.php';\n");
        self::assertNotNull($ast);
        $nodes = array_values($ast);
        $finder = new \PhpParser\NodeFinder();
        $includes = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Include_;
        });
        self::assertNotEmpty($includes);
        $include = $includes[0];
        self::assertInstanceOf(Node\Expr\Include_::class, $include);
        $scope = ConstantScope::forFile($nodes, 'routes/web.php');
        $value = (new ConstantValueResolver())->resolve($include->expr, $scope, $include->getStartLine());

        self::assertSame('routes/admin.php', str_replace('\\', '/', (string) $value?->value));
    }

    public function testUnassignedVariableIsNull(): void
    {
        ['scope' => $scope, 'calls' => $calls] = $this->scopeOf(
            "use Illuminate\\Support\\Facades\\Route;\nRoute::get('/x', \$controller);\n"
        );
        $arg = $calls[0]->args[1];
        self::assertInstanceOf(Node\Arg::class, $arg);
        $resolver = new ConstantValueResolver();

        self::assertNull($resolver->resolve($arg->value, $scope, $calls[0]->getStartLine()));
        self::assertSame('unassigned-variable', $resolver->failureReason());
    }

    public function testUseBeforeAssignIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "Route::get('/x', \$controller);\n" .
            "\$controller = 'App\\\\Http\\\\Controllers\\\\C@show';\n"
        );

        self::assertNull($value);
    }

    public function testRepeatedAssignmentIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$controller = 'App\\\\Http\\\\Controllers\\\\A@show';\n" .
            "\$controller = 'App\\\\Http\\\\Controllers\\\\B@show';\n" .
            "Route::get('/x', \$controller);\n"
        );

        self::assertNull($value);
    }

    public function testConditionalReassignmentIsNull(): void
    {
        // The gate's key negative case: one path keeps 'Admin'.
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$x = 'Admin';\n" .
            "if (\$condition) {\n" .
            "    \$x = 'User';\n" .
            "}\n" .
            "Route::get('/', \$x . 'Controller@index');\n"
        );

        self::assertNull($value);
    }

    public function testNoCrossFunctionLeakage(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$x = 'Safe';\n" .
            "function foo() {\n" .
            "    Route::get('/x', \$x);\n" .
            "}\n",
            0
        );

        self::assertNull($value);
    }

    public function testFunctionLocalAssignmentResolves(): void
    {
        ['scope' => $scope, 'calls' => $calls] = $this->scopeOf(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "function boot() {\n" .
            "    \$controller = 'App\\\\Http\\\\Controllers\\\\C@show';\n" .
            "    Route::get('/x', \$controller);\n" .
            "}\n"
        );
        $call = $calls[0];
        $arg = $call->args[1];
        self::assertInstanceOf(Node\Arg::class, $arg);
        $fnScope = $scope->forNode($call);
        $value = (new ConstantValueResolver())->resolve($arg->value, $fnScope, $call->getStartLine());

        self::assertSame('App\\Http\\Controllers\\C@show', $value?->value);
    }

    public function testRequestCallIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$controller = request('controller');\n" .
            "Route::get('/', \$controller);\n"
        );

        self::assertNull($value);
    }

    public function testConfigCallIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$controller = config('app.controller');\n" .
            "Route::get('/', \$controller);\n"
        );

        self::assertNull($value);
    }

    public function testMethodCallIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "Route::get('/x', \$this->controller());\n"
        );

        self::assertNull($value);
    }

    public function testCyclicAssignmentIsNull(): void
    {
        $value = $this->resolveTarget(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$a = \$b;\n" .
            "\$b = \$a;\n" .
            "Route::get('/x', \$a);\n"
        );

        self::assertNull($value);
    }

    public function testProvenanceChain(): void
    {
        ['scope' => $scope, 'calls' => $calls] = $this->scopeOf(
            "use Illuminate\\Support\\Facades\\Route;\n" .
            "\$prefix = 'App\\\\Http\\\\Controllers\\\\';\n" .
            "\$controller = \$prefix . 'C@show';\n" .
            "Route::get('/x', \$controller);\n"
        );
        $call = $calls[0];
        $arg = $call->args[1];
        self::assertInstanceOf(Node\Arg::class, $arg);
        $value = (new ConstantValueResolver())->resolve($arg->value, $scope, $call->getStartLine());

        self::assertNotNull($value);
        self::assertSame('exact', $value->confidence);
        $kinds = array_column($value->provenance, 'kind');
        self::assertContains('literal', $kinds);
        self::assertContains('variable', $kinds);
        self::assertContains('concat', $kinds);
    }

    public function testBasePathHelperResolves(): void
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $ast = $parser->parse("<?php\nrequire base_path('routes/api.php');\n");
        self::assertNotNull($ast);
        $nodes = array_values($ast);
        $finder = new \PhpParser\NodeFinder();
        $includes = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Include_;
        });
        self::assertNotEmpty($includes);
        $include = $includes[0];
        self::assertInstanceOf(Node\Expr\Include_::class, $include);
        $scope = ConstantScope::forFile($nodes, 'app/Providers/RouteServiceProvider.php');
        $value = (new ConstantValueResolver())->resolve($include->expr, $scope, $include->getStartLine());

        self::assertSame('routes/api.php', $value?->value);
    }
}
