<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PhpParser\Node;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analysis\AstPool;

final class AstPoolTest extends TestCase
{
    private function tempPhp(string $content): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-pool-' . uniqid('', true) . '.php';
        file_put_contents($path, $content);

        return $path;
    }

    public function testParsesFileOnceAndCaches(): void
    {
        $file = $this->tempPhp("<?php\n\$a = 1;\n");
        $pool = new AstPool();

        $first = $pool->ast($file);
        $second = $pool->ast($file);

        self::assertNotNull($first);
        self::assertSame($first, $second);
        self::assertSame(['hits' => 1, 'misses' => 1, 'files' => 1], $pool->stats());
    }

    public function testReturnsNullForMissingOrUnparseable(): void
    {
        $pool = new AstPool();

        self::assertNull($pool->ast(sys_get_temp_dir() . '/qc-pool-missing-' . uniqid('', true) . '.php'));

        $bad = $this->tempPhp("<?php\nfunction ({\n");
        self::assertNull($pool->ast($bad));
    }

    public function testClearResetsCache(): void
    {
        $file = $this->tempPhp("<?php\n\$a = 1;\n");
        $pool = new AstPool();
        $pool->ast($file);
        $pool->clear();

        self::assertSame(['hits' => 0, 'misses' => 0, 'files' => 0], $pool->stats());
    }

    public function testAstContainsNodes(): void
    {
        $file = $this->tempPhp("<?php\nfunction hello(): string {\n    return 'hi';\n}\n");
        $ast = (new AstPool())->ast($file);

        self::assertNotNull($ast);
        $funcs = array_filter($ast, static fn ($node): bool => $node instanceof Node\Stmt\Function_);
        self::assertCount(1, $funcs);
    }
}
