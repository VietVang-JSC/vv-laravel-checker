<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analysis\AssignmentMap;
use Rampart\QualityChecker\Analysis\FlowTrace;
use Rampart\QualityChecker\Analysis\ScopeResolver;

final class AnalysisPrimitivesTest extends TestCase
{
    /** @return list<Node> */
    private function parse(string $code): array
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $ast = $parser->parse($code);
        self::assertNotNull($ast);
        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    public function testScopeResolverSeparatesFunctions(): void
    {
        $nodes = $this->parse("<?php\nclass C {\n public function a(): void {\n \$x = 1;\n }\n public function b(): void {\n \$y = 2;\n }\n}\n\$z = 3;\n");
        $scopes = new ScopeResolver();

        $funcs = $scopes->functions($nodes);

        self::assertCount(2, $funcs);
    }

    public function testAssignmentMapOriginsIncludeExtendedSources(): void
    {
        $nodes = $this->parse("<?php\nclass C {\n public function m(array \$files): void {\n \$out['k'] = glob('d/*');\n foreach (\$files as \$f) {\n \$this->api = env('U');\n }\n }\n}\n");
        $origins = (new AssignmentMap())->origins($nodes);

        self::assertArrayHasKey('out', $origins);
        self::assertArrayHasKey('f', $origins);
        self::assertArrayHasKey('this->api', $origins);
    }

    public function testAssignmentMapVisibleRespectsScopeAndOrder(): void
    {
        $nodes = $this->parse(
            "<?php\nclass C {\n public function a(): void {\n \$x = 'lit';\n }\n public function b(string \$y): void {\n \$sink = \$y;\n \$z = 'after';\n }\n}\n"
        );
        $map = new AssignmentMap();
        $scopes = new ScopeResolver();

        $funcs = array_values($scopes->functions($nodes));
        self::assertCount(2, $funcs);

        // Find the $sink = $y assignment line to use as sink line.
        $finder = new NodeFinder();
        $assigns = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Expr\Assign;
        });
        $sinkLine = 0;
        $funcBId = 0;
        foreach ($assigns as $assign) {
            if (
                $assign instanceof Node\Expr\Assign
                && $assign->var instanceof Node\Expr\Variable
                && $assign->var->name === 'sink'
            ) {
                $sinkLine = $assign->getStartLine();
                $funcBId = $scopes->funcId($assign, $nodes);
            }
        }
        self::assertGreaterThan(0, $sinkLine);
        self::assertGreaterThan(0, $funcBId);

        $visible = $map->visible($nodes, $funcBId, $sinkLine + 10);
        $names = [];
        foreach ($visible as $assign) {
            if ($assign->var instanceof Node\Expr\Variable && is_string($assign->var->name)) {
                $names[] = $assign->var->name;
            }
        }
        // $sink and $z are straight-line assigns in b(); $x lives in a().
        self::assertContains('sink', $names);
        self::assertContains('z', $names);
        self::assertNotContains('x', $names);
    }

    public function testFlowTraceDescribesSteps(): void
    {
        $trace = (new FlowTrace())
            ->source('request input', 3)
            ->propagate('$target assigned', 5)
            ->sink('redirect()->to()', 9);

        $metadata = $trace->toMetadata();

        self::assertCount(3, $metadata);
        self::assertSame('source', $metadata[0]['kind']);
        self::assertStringContainsString('request input', $trace->describe());
        self::assertStringContainsString('redirect()->to()', $trace->describe());
        self::assertTrue((new FlowTrace())->isEmpty());
    }
}
