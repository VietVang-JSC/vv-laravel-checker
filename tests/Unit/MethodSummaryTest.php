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
use Rampart\QualityChecker\Semantic\MethodSummary;
use Rampart\QualityChecker\Semantic\MethodSummaryIndex;

/**
 * v0.5.2 bounded interprocedural return summaries: corpus Aâ€“T.
 * Soundness first â€” unresolved beats wrong, always.
 */
final class MethodSummaryTest extends TestCase
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
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-sum-' . uniqid('', true);
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

    /**
     * @return array{nodes: list<Node>, class: Node\Stmt\Class_, method: Node\Stmt\ClassMethod, uses: array<string, string>, namespace: string|null}
     */
    private function parse(string $path): array
    {
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse((string) file_get_contents($path));
        self::assertNotNull($ast);
        $nodes = array_values($ast);
        $finder = new NodeFinder();
        $class = null;
        foreach ($finder->find($nodes, static fn (Node $n): bool => $n instanceof Node\Stmt\Class_) as $c) {
            if ($c instanceof Node\Stmt\Class_) {
                $class = $c;
                break;
            }
        }
        self::assertNotNull($class);
        $method = null;
        foreach ($finder->find($nodes, static fn (Node $n): bool => $n instanceof Node\Stmt\ClassMethod) as $m) {
            if ($m instanceof Node\Stmt\ClassMethod && strtolower($m->name->toString()) === 'store') {
                $method = $m;
                break;
            }
        }
        self::assertNotNull($method);
        $uses = [];
        $namespace = null;
        foreach ($finder->find($nodes, static fn (Node $n): bool => $n instanceof Node\Stmt\Use_ || $n instanceof Node\Stmt\Namespace_) as $u) {
            if ($u instanceof Node\Stmt\Namespace_ && $u->name instanceof Node\Name) {
                $namespace = $u->name->toString();
            }
            if ($u instanceof Node\Stmt\Use_ && $u->type === Node\Stmt\Use_::TYPE_NORMAL) {
                foreach ($u->uses as $uu) {
                    if ($uu instanceof Node\Stmt\UseUse) {
                        $alias = $uu->alias !== null ? $uu->alias->toString() : $uu->name->getLast();
                        $uses[strtolower($alias)] = $uu->name->toString();
                    }
                }
            }
        }

        return ['nodes' => $nodes, 'class' => $class, 'method' => $method, 'uses' => $uses, 'namespace' => $namespace];
    }

    private function service(string $body, string $class = 'UserService'): string
    {
        return "<?php\nnamespace App\\Services;\n" .
            "class {$class} {\n" .
            "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
            "        {$body}\n" .
            "    }\n" .
            "}\n";
    }

    private function controller(string $body): string
    {
        return "<?php\nnamespace App\\Http\\Controllers;\n" .
            "use App\\Services\\UserService;\n" .
            "class UserController extends Controller {\n" .
            "    public function __construct(private UserService \$service) {}\n" .
            "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
            "        {$body}\n" .
            "    }\n" .
            "}\n";
    }

    /**
     * @param list<string> $paths
     */
    private function classifySink(string $controllerPath, array $paths, string $body): MassFlow
    {
        // Rewrite controller body per case is complex; instead each case
        // builds its own project â€” this helper classifies the FIRST
        // create()/fill() sink in the already-written controller.
        $parsed = $this->parse($controllerPath);
        $finder = new NodeFinder();
        $sinks = $finder->find($parsed['nodes'], static function (Node $n): bool {
            return ($n instanceof Node\Expr\StaticCall || $n instanceof Node\Expr\MethodCall)
                && $n->name instanceof Node\Identifier
                && in_array(strtolower($n->name->toString()), ['create', 'fill', 'update'], true);
        });
        self::assertNotEmpty($sinks);
        $sink = $sinks[0];
        self::assertTrue($sink instanceof Node\Expr\StaticCall || $sink instanceof Node\Expr\MethodCall);
        $arg = $sink->args[0] ?? null;
        self::assertInstanceOf(Node\Arg::class, $arg);
        $index = new MethodSummaryIndex($paths);
        $funcId = (new ScopeResolver($finder))->funcId($sink, $parsed['nodes']);

        return MassAssignmentFlow::classify(
            $arg->value,
            $sink->name instanceof Node\Identifier ? $sink->name->toString() : 'create',
            $parsed['method'],
            $parsed['nodes'],
            $funcId,
            $controllerPath,
            $sink->getStartLine(),
            $index,
            $parsed['class'],
            $parsed['uses'],
            $parsed['namespace']
        );
    }

    /**
     * @param array<string, string> $files
     */
    private function flowStatus(array $files, string $controllerBody): string
    {
        $paths = $this->project($files);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        self::assertNotNull($controllerPath);

        return $this->classifySink($controllerPath, $paths, $controllerBody)->status;
    }

    public function testServiceReturnsAllIsRaw(): void
    {
        // A.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->all();'),
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::RAW, $status);
    }

    public function testServiceReturnsValidated(): void
    {
        // B.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->validated();'),
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::VALIDATED, $status);
    }

    public function testServiceReturnsOnlyIsBounded(): void
    {
        // C.
        $paths = $this->project([
            'app/Services/UserService.php' => $this->service("return \$request->only(['name', 'email']);"),
            'app/Http/Controllers/UserController.php' => $this->controller(
                '$data = $this->service->payload($request); User::create($data);'
            ),
        ]);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        $flow = $this->classifySink($controllerPath, $paths, '');

        self::assertSame(MassFlow::BOUNDED, $flow->status);
        self::assertSame(['name', 'email'], $flow->fields);
    }

    public function testServiceReturnsLiteralIsInternal(): void
    {
        // D.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service("return ['name' => 'seed'];"),
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::INTERNAL, $status);
    }

    public function testConditionalMixedReturnsAreUnknown(): void
    {
        // E.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function payload(\\Illuminate\\Http\\Request \$request, \$flag) {\n" .
                    "        if (\$flag) {\n" .
                    "            return \$request->validated();\n" .
                    "        }\n" .
                    "        return \$request->all();\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request, true); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::UNKNOWN, $status);
    }

    public function testRecursiveServiceIsUnknown(): void
    {
        // F + S: Aâ†’Bâ†’A cycle stops, no hang.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function payload(\$x) {\n" .
                    "        return \$this->payload(\$x);\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::UNKNOWN, $status);
    }

    public function testDynamicMethodIsUnknown(): void
    {
        // G.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->all();'),
                'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                    "use App\\Services\\UserService;\n" .
                    "class UserController extends Controller {\n" .
                    "    public function __construct(private UserService \$service) {}\n" .
                    "    public function store(\\Illuminate\\Http\\Request \$request, \$m) {\n" .
                    "        \$data = \$this->service->\$m(\$request); User::create(\$data);\n" .
                    "    }\n" .
                    "}\n",
            ],
            ''
        );

        self::assertSame(MassFlow::UNKNOWN, $status);
    }

    public function testSameMethodNameResolvesCorrectClass(): void
    {
        // H + K: two payload() methods, different classes/returns.
        $paths = $this->project([
            'app/Services/UserService.php' => $this->service('return $request->all();'),
            'app/Services/OrderService.php' => "<?php\nnamespace App\\Services;\n" .
                "class OrderService {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->validated();\n" .
                "    }\n" .
                "}\n",
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "use App\\Services\\UserService;\nuse App\\Services\\OrderService;\n" .
                "class UserController extends Controller {\n" .
                "    public function __construct(private UserService \$userService, private OrderService \$orderService) {}\n" .
                "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                "        \$data = \$this->orderService->payload(\$request); User::create(\$data);\n" .
                "    }\n" .
                "}\n",
        ]);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        $flow = $this->classifySink($controllerPath, $paths, '');

        // orderService::payload returns validated â€” not userService's raw.
        self::assertSame(MassFlow::VALIDATED, $flow->status);
    }

    public function testUntypedServiceIsUnknown(): void
    {
        // M.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->all();'),
                'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                    "class UserController extends Controller {\n" .
                    "    private \$service;\n" .
                    "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                    "        \$data = \$this->service->payload(\$request); User::create(\$data);\n" .
                    "    }\n" .
                    "}\n",
            ],
            ''
        );

        self::assertSame(MassFlow::UNKNOWN, $status);
    }

    public function testIdenticalBranchReturnsResolve(): void
    {
        // N.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function payload(\\Illuminate\\Http\\Request \$request, \$flag) {\n" .
                    "        if (\$flag) {\n" .
                    "            return \$request->all();\n" .
                    "        }\n" .
                    "        return \$request->all();\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request, true); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::RAW, $status);
    }

    public function testPassthroughRawIsRaw(): void
    {
        // P.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function wrap(\$input) {\n" .
                    "        return \$input;\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->wrap($request->all()); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::RAW, $status);
    }

    public function testPassthroughInternalIsInternal(): void
    {
        // Q.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function wrap(\$input) {\n" .
                    "        return \$input;\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    "\$data = \$this->service->wrap(['a' => 'b']); User::create(\$data);"
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::INTERNAL, $status);
    }

    public function testNestedCallIsUnknownWithReason(): void
    {
        // R.
        $paths = $this->project([
            'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                "class UserService {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$this->transform(\$request->all());\n" .
                "    }\n" .
                "    private function transform(\$x) {\n" .
                "        return \$x;\n" .
                "    }\n" .
                "}\n",
            'app/Http/Controllers/UserController.php' => $this->controller(
                '$data = $this->service->payload($request); User::create($data);'
            ),
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\UserService', 'payload');

        self::assertSame(MethodSummary::UNKNOWN, $summary->kind);
        self::assertSame('nested-call', $summary->unresolvedReason);
    }

    public function testSummaryCache(): void
    {
        // T.
        $paths = $this->project([
            'app/Services/UserService.php' => $this->service('return $request->all();'),
        ]);
        $index = new MethodSummaryIndex($paths);
        $first = $index->summary('App\\Services\\UserService', 'payload');
        $second = $index->summary('App\\Services\\UserService', 'payload');

        self::assertSame(MethodSummary::PARAM, $first->kind);
        self::assertSame($first->toArray(), $second->toArray());
        $stats = $index->stats();
        self::assertSame(2, $stats['requests']);
        self::assertSame(1, $stats['hits']);
        self::assertSame(1, $stats['misses']);
        self::assertSame(1, $stats['methods']);
        self::assertSame(1, $stats['ast_parses']);
    }

    public function testConstructorAssignmentResolves(): void
    {
        // L (non-promoted bounded DI).
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->validated();'),
                'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                    "use App\\Services\\UserService;\n" .
                    "class UserController extends Controller {\n" .
                    "    private UserService \$service;\n" .
                    "    public function __construct(UserService \$service) {\n" .
                    "        \$this->service = \$service;\n" .
                    "    }\n" .
                    "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                    "        \$data = \$this->service->payload(\$request); User::create(\$data);\n" .
                    "    }\n" .
                    "}\n",
            ],
            ''
        );

        self::assertSame(MassFlow::VALIDATED, $status);
    }

    public function testReassignmentBeforeCallUsesCorrectArg(): void
    {
        // I.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => "<?php\nnamespace App\\Services;\n" .
                    "class UserService {\n" .
                    "    public function wrap(\$input) {\n" .
                    "        return \$input;\n" .
                    "    }\n" .
                    "}\n",
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$tmp = $request->validated(); $data = $this->service->wrap($tmp); User::create($data);'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::VALIDATED, $status);
    }

    public function testReassignmentAfterCallIsIrrelevant(): void
    {
        // J: the sink sees the pre-reassignment value.
        $status = $this->flowStatus(
            [
                'app/Services/UserService.php' => $this->service('return $request->all();'),
                'app/Http/Controllers/UserController.php' => $this->controller(
                    '$data = $this->service->payload($request); User::create($data); $data = $other;'
                ),
            ],
            ''
        );

        self::assertSame(MassFlow::RAW, $status);
    }

    /**
     * @param array<string, string> $extra
     * @return list<string>
     */
    private function hierarchyProject(array $extra = []): array
    {
        return $this->project(array_merge(
            [
                'app/Services/BaseImporter.php' => "<?php\nnamespace App\\Services;\n" .
                    "class BaseImporter {\n" .
                    "    protected function sanitize(\$data) {\n" .
                    "        return \$data;\n" .
                    "    }\n" .
                    "}\n",
            ],
            $extra
        ));
    }

    public function testDirectParentMethodResolves(): void
    {
        // U.
        $paths = $this->hierarchyProject([
            'app/Services/ItemImporter.php' => "<?php\nnamespace App\\Services;\n" .
                "class ItemImporter extends BaseImporter {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\ItemImporter', 'sanitize');

        self::assertSame(MethodSummary::PARAM, $summary->kind);
        self::assertSame('App\\Services\\BaseImporter', $summary->declaringClass);
    }

    public function testGrandparentMethodResolves(): void
    {
        // V.
        $paths = $this->hierarchyProject([
            'app/Services/ItemImporter.php' => "<?php\nnamespace App\\Services;\n" .
                "class ItemImporter extends BaseImporter {\n" .
                "}\n",
            'app/Services/AccessoryImporter.php' => "<?php\nnamespace App\\Services;\n" .
                "class AccessoryImporter extends ItemImporter {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\AccessoryImporter', 'sanitize');

        self::assertSame(MethodSummary::PARAM, $summary->kind);
        self::assertSame('App\\Services\\BaseImporter', $summary->declaringClass);
    }

    public function testChildOverrideWins(): void
    {
        // W.
        $paths = $this->project([
            'app/Services/Base.php' => "<?php\nnamespace App\\Services;\n" .
                "class Base {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->all();\n" .
                "    }\n" .
                "}\n",
            'app/Services/Child.php' => "<?php\nnamespace App\\Services;\n" .
                "class Child extends Base {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->validated();\n" .
                "    }\n" .
                "}\n",
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "use App\\Services\\Child;\n" .
                "class UserController extends Controller {\n" .
                "    private Child \$svc;\n" .
                "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                "        \$data = \$this->svc->payload(\$request); User::create(\$data);\n" .
                "    }\n" .
                "}\n",
        ]);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        $flow = $this->classifySink($controllerPath, $paths, '');

        // Child::payload (validated), not Base::payload (raw).
        self::assertSame(MassFlow::VALIDATED, $flow->status);
    }

    public function testParentCallTargetsParent(): void
    {
        // X.
        $paths = $this->project([
            'app/Services/Base.php' => "<?php\nnamespace App\\Services;\n" .
                "class Base {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->all();\n" .
                "    }\n" .
                "}\n",
            'app/Services/Child.php' => "<?php\nnamespace App\\Services;\n" .
                "class Child extends Base {\n" .
                "    public function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->validated();\n" .
                "    }\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->parentSummary('App\\Services\\Child', 'payload');

        self::assertSame(MethodSummary::PARAM, $summary->kind);
        self::assertSame('App\\Services\\Base', $summary->declaringClass);
        self::assertSame(MethodSummary::OP_ALL, $summary->operation);
    }

    public function testPrivateParentMethodNotInherited(): void
    {
        // Y.
        $paths = $this->project([
            'app/Services/Base.php' => "<?php\nnamespace App\\Services;\n" .
                "class Base {\n" .
                "    private function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->all();\n" .
                "    }\n" .
                "}\n",
            'app/Services/Child.php' => "<?php\nnamespace App\\Services;\n" .
                "class Child extends Base {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\Child', 'payload');

        self::assertSame(MethodSummary::UNKNOWN, $summary->kind);
        self::assertSame('unresolved-method', $summary->unresolvedReason);
    }

    public function testProtectedParentMethodWorks(): void
    {
        // Z.
        $paths = $this->hierarchyProject([
            'app/Services/ItemImporter.php' => "<?php\nnamespace App\\Services;\n" .
                "class ItemImporter extends BaseImporter {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\ItemImporter', 'sanitize');

        self::assertSame(MethodSummary::PARAM, $summary->kind);
        self::assertSame('protected', $summary->visibility);
    }

    public function testProtectedMethodOnOtherObjectIsUnknown(): void
    {
        // Visibility gate: protected members are only reachable through
        // $this — calling them on another object would fatal at runtime.
        $paths = $this->project([
            'app/Services/Base.php' => "<?php\nnamespace App\\Services;\n" .
                "class Base {\n" .
                "    protected function payload(\\Illuminate\\Http\\Request \$request) {\n" .
                "        return \$request->all();\n" .
                "    }\n" .
                "}\n",
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "use App\\Services\\Base;\n" .
                "class UserController extends Controller {\n" .
                "    private Base \$svc;\n" .
                "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                "        \$data = \$this->svc->payload(\$request); User::create(\$data);\n" .
                "    }\n" .
                "}\n",
        ]);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        $flow = $this->classifySink($controllerPath, $paths, '');

        self::assertSame(MassFlow::UNKNOWN, $flow->status);
    }

    public function testUnresolvedParentClassIsUnknown(): void
    {
        // AA.
        $paths = $this->project([
            'app/Services/Child.php' => "<?php\nnamespace App\\Services;\n" .
                "class Child extends MissingBase {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\Child', 'payload');

        self::assertSame(MethodSummary::UNKNOWN, $summary->kind);
        self::assertSame('unresolved-class', $summary->unresolvedReason);
    }

    public function testInheritanceCycleIsBounded(): void
    {
        // AB: malformed Aâ†”B cycle terminates.
        $paths = $this->project([
            'app/Services/A.php' => "<?php\nnamespace App\\Services;\nclass A extends B {}\n",
            'app/Services/B.php' => "<?php\nnamespace App\\Services;\nclass B extends A {}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Services\\A', 'payload');

        self::assertSame(MethodSummary::UNKNOWN, $summary->kind);
    }

    public function testNoCrossTreeResolution(): void
    {
        // AC: same method name in an unrelated tree never resolves.
        $paths = $this->project([
            'app/Services/BaseImporter.php' => "<?php\nnamespace App\\Services;\n" .
                "class BaseImporter {\n" .
                "    protected function sanitize(\$data) {\n" .
                "        return \$data;\n" .
                "    }\n" .
                "}\n",
            'app/Other/Worker.php' => "<?php\nnamespace App\\Other;\n" .
                "class Worker {\n" .
                "}\n",
        ]);
        $index = new MethodSummaryIndex($paths);
        $summary = $index->summary('App\\Other\\Worker', 'sanitize');

        self::assertSame(MethodSummary::UNKNOWN, $summary->kind);
        self::assertSame('unresolved-method', $summary->unresolvedReason);
    }

    public function testInheritedPassthroughPreservesProvenance(): void
    {
        // AD: Child call â†’ inherited Base::payload â†’ PARAM(0) â†’ caller
        // arg RAW. This is the v0.5.2+v0.5.3 join proving itself.
        $paths = $this->project([
            'app/Services/Base.php' => "<?php\nnamespace App\\Services;\n" .
                "class Base {\n" .
                "    public function payload(\$input) {\n" .
                "        return \$input;\n" .
                "    }\n" .
                "}\n",
            'app/Services/Child.php' => "<?php\nnamespace App\\Services;\n" .
                "class Child extends Base {\n" .
                "}\n",
            'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\n" .
                "use App\\Services\\Child;\n" .
                "class UserController extends Controller {\n" .
                "    private Child \$svc;\n" .
                "    public function store(\\Illuminate\\Http\\Request \$request) {\n" .
                "        \$data = \$this->svc->payload(\$request->all()); User::create(\$data);\n" .
                "    }\n" .
                "}\n",
        ]);
        $controllerPath = null;
        foreach ($paths as $path) {
            if (str_ends_with($path, 'UserController.php')) {
                $controllerPath = $path;
            }
        }
        $flow = $this->classifySink($controllerPath, $paths, '');

        self::assertSame(MassFlow::RAW, $flow->status);
    }
}
