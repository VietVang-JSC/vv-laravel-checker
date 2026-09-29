<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analysis\ScopeResolver;
use Rampart\QualityChecker\Semantic\MassAssignmentFlow;
use Rampart\QualityChecker\Semantic\MassFlow;

/**
 * v0.4.1 input-to-sink classification: the same `User::create($data)`
 * sink with different provenances must classify differently.
 */
final class MassAssignmentFlowTest extends TestCase
{
    /**
     * @return array{nodes: list<Node>, method: Node\Stmt\ClassMethod, sink: Node\Expr\StaticCall|Node\Expr\MethodCall, funcId: int}
     */
    private function sinkOf(string $body, string $methodName = 'store'): array
    {
        // One statement per line: shared-engine visibility is line-based.
        $lines = array_map(
            static fn ($s): string => '        ' . trim($s) . ';',
            array_filter(array_map('trim', explode(';', $body)))
        );
        $code = "<?php\nnamespace App\\Http\\Controllers;\n" .
            "class UserController extends Controller {\n" .
            "    public function {$methodName}(\\Illuminate\\Http\\Request \$request) {\n" .
            implode("\n", $lines) . "\n" .
            "    }\n" .
            "}\n";
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($code);
        self::assertNotNull($ast);
        $nodes = array_values($ast);
        $finder = new NodeFinder();
        $methods = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod;
        });
        $method = $methods[0];
        self::assertInstanceOf(Node\Stmt\ClassMethod::class, $method);
        $sinks = $finder->find($nodes, static function (Node $node): bool {
            return ($node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall)
                && $node->name instanceof Node\Identifier
                && in_array(strtolower($node->name->toString()), ['create', 'fill', 'update', 'forcefill', 'forcecreate'], true);
        });
        self::assertNotEmpty($sinks);
        $sink = $sinks[0];
        self::assertTrue($sink instanceof Node\Expr\StaticCall || $sink instanceof Node\Expr\MethodCall);
        $funcId = (new ScopeResolver($finder))->funcId($sink, $nodes);

        return ['nodes' => $nodes, 'method' => $method, 'sink' => $sink, 'funcId' => $funcId];
    }

    private function classifySink(string $body): MassFlow
    {
        ['nodes' => $nodes, 'method' => $method, 'sink' => $sink, 'funcId' => $funcId] = $this->sinkOf($body);
        $arg = $sink->args[0] ?? null;
        self::assertInstanceOf(Node\Arg::class, $arg);
        $name = $sink->name instanceof Node\Identifier ? $sink->name->toString() : 'create';

        return MassAssignmentFlow::classify(
            $arg->value,
            $name,
            $method,
            $nodes,
            $funcId,
            'app/Http/Controllers/UserController.php',
            $sink->getStartLine()
        );
    }

    public function testRequestAllIsRaw(): void
    {
        // A. request()->all() → tainted/raw.
        $flow = $this->classifySink('User::create($request->all());');

        self::assertSame(MassFlow::RAW, $flow->status);
        self::assertFalse($flow->forceBypass);
        self::assertNotEmpty($flow->trace);
    }

    public function testValidatedIsValidated(): void
    {
        // B. $request->validated() → validated (not a safety verdict).
        $flow = $this->classifySink('$data = $request->validated(); User::create($data);');

        self::assertSame(MassFlow::VALIDATED, $flow->status);
        self::assertNull($flow->fields);
    }

    public function testOnlyIsBounded(): void
    {
        // C. $request->only([...]) → bounded with fields.
        $flow = $this->classifySink("User::create(\$request->only(['name', 'email']));");

        self::assertSame(MassFlow::BOUNDED, $flow->status);
        self::assertSame(['name', 'email'], $flow->fields);
    }

    public function testLiteralIsInternal(): void
    {
        // D. literal array → internal, never request-tainted.
        $flow = $this->classifySink("User::create(['name' => 'seed']);");

        self::assertSame(MassFlow::INTERNAL, $flow->status);
    }

    public function testServiceReturnIsUnknown(): void
    {
        // E. service return → unknown.
        $flow = $this->classifySink('$data = $this->service->buildData(); User::create($data);');

        self::assertSame(MassFlow::UNKNOWN, $flow->status);
    }

    public function testConditionalMixIsUnknown(): void
    {
        // F. conditional raw/safe mix → unknown, never false-safe.
        $flow = $this->classifySink(
            '$data = $request->all();' .
            ' if ($x) { $data = $request->validated(); }' .
            ' User::create($data);'
        );

        self::assertSame(MassFlow::UNKNOWN, $flow->status);
    }

    public function testForceFillIsBypass(): void
    {
        $flow = $this->classifySink('$user->forceFill($request->all());');

        self::assertSame(MassFlow::RAW, $flow->status);
        self::assertTrue($flow->forceBypass);
        self::assertSame('forceFill()', $flow->sink);
    }

    public function testExceptKeepsRawWithExclusions(): void
    {
        $flow = $this->classifySink("User::create(\$request->except(['is_admin']));");

        self::assertSame(MassFlow::RAW, $flow->status);
        self::assertSame(['is_admin'], $flow->excluded);
    }

    public function testSafeOnlyIsValidatedBounded(): void
    {
        $flow = $this->classifySink("User::create(\$request->safe()->only(['name']));");

        self::assertSame(MassFlow::BOUNDED, $flow->status);
        self::assertSame(['name'], $flow->fields);
    }

    public function testChainedVariablePropagates(): void
    {
        $flow = $this->classifySink('$a = $request->all(); $data = $a; User::create($data);');

        self::assertSame(MassFlow::RAW, $flow->status);
        $kinds = array_column($flow->trace, 'kind');
        self::assertContains('propagation', $kinds);
    }

    public function testTraceHasSourceAndSink(): void
    {
        $flow = $this->classifySink('$data = $request->validated(); User::create($data);');

        $kinds = array_column($flow->trace, 'kind');
        self::assertContains('source', $kinds);
        self::assertContains('sink', $kinds);
        self::assertSame('create()', $flow->sink);
    }
}
