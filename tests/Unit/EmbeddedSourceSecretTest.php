<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;

/**
 * Secrets written inside a string that holds source code are not secrets.
 *
 * A test that plants a vulnerable fixture writes the file as one string, and
 * with escaped newlines that is a single physical line:
 *
 *     $this->tempPhp("<?php\nclass Api {\n  private string $k = 'sk-ABC…';\n}\n");
 *
 * A line-based scanner reads the key and reports a critical leak for source
 * that is never executed. This package's own suite hit it five times on the
 * first run, which is exactly the first impression a developer gets from a
 * freshly cloned tool.
 *
 * The corpus in AnalyzerMetricsTest is the regression guard in the other
 * direction: a real key on its own line must still be found.
 */
final class EmbeddedSourceSecretTest extends TestCase
{
    private string $dir = '';

    protected function tearDown(): void
    {
        if ($this->dir !== '' && is_dir($this->dir)) {
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($this->dir);
        }
        $this->dir = '';
        parent::tearDown();
    }

    /**
     * @return list<\Rampart\QualityChecker\Result\Issue>
     */
    private function analyze(string $contents, string $relative = 'app/Services/ApiService.php'): array
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-embedsrc-' . uniqid('', true);
        @mkdir($this->dir, 0777, true);
        $path = $this->dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $contents);

        return (new HardcodedSecretAnalyzer())->analyze([$path]);
    }

    /**
     * The shape that produced five false positives on this package's own suite.
     */
    public function testSecretInsideAnEmbeddedSourceStringIsNotReported(): void
    {
        $test = "<?php\nclass HelperTest extends TestCase {\n"
            . "    public function test_key() {\n"
            . "        \$file = \"<?php\\nclass ApiService {\\n    private string \\\$key = 'sk-ABC12345678901234567890';\\n}\\n\";\n"
            . "    }\n}\n";

        self::assertSame([], $this->analyze($test, 'tests/Unit/HelperTest.php'));
    }

    public function testSecretInsideAConfigWrittenByASeederIsNotReported(): void
    {
        $seeder = "<?php\nclass DataSeeder extends Seeder {\n"
            . "    public function run() {\n"
            . "        \$contents = \"<?php\\nreturn ['key' => 'whsec_aB3x9QwE7rT2yU4iO6pQ8s'];\\n\";\n"
            . "    }\n}\n";

        self::assertSame([], $this->analyze($seeder, 'database/seeders/DataSeeder.php'));
    }

    public function testRealSecretOnItsOwnLineIsStillReported(): void
    {
        // One physical line, so this is genuinely an assignment in executed code
        // and not embedded source. Written as concatenated lines it would be
        // flagged too — see the class comment on that limitation.
        $service = "<?php\nclass ApiService {\n    private string \$key = 'sk-ABC12345678901234567890';\n}\n";

        $issues = $this->analyze($service);

        self::assertCount(1, $issues, 'A real hardcoded key must still be a critical finding.');
        self::assertSame('HARDCODED_SECRET', $issues[0]->rule);
    }

    public function testRealSecretInATestFileIsStillReported(): void
    {
        // tests/ is not a blanket exclusion: a leaked key in a test helper is
        // still a leaked key, and only the fake-fixture heuristics apply there.
        $test = "<?php\nclass HelperTest extends TestCase {\n    public function test_it() {\n        \$key = 'sk-ABC12345678901234567890';\n    }\n}\n";

        self::assertCount(1, $this->analyze($test, 'tests/Unit/HelperTest.php'));
    }

    /**
     * The known limit of a line-based scanner, pinned so it is a decision rather
     * than a surprise: when the embedded source is split across concatenated
     * string literals, the `<?php` marker sits on an earlier physical line and the
     * key on this one, so this reads as an assignment and is reported.
     *
     * Making that case silent needs AST-aware matching — asking whether the match
     * sits inside a string node — not a wider line heuristic. Until then it is a
     * false positive, it is rare outside fixture-writing tests, and saying so is
     * better than a heuristic that quietly hides real secrets.
     */
    public function testConcatenatedEmbeddedSourceIsStillReported(): void
    {
        $test = "<?php\nclass HelperTest extends TestCase {\n"
            . "    public function test_it() {\n"
            . "        \$src = \"<?php\\nclass Api {\\n\"\n"
            // quality-checker-ignore-next-line HARDCODED_SECRET
            . "            . \"    private string \$key = 'sk-ABC12345678901234567890';\\n}\\n\";\n"
            . "    }\n}\n";

        self::assertCount(
            1,
            $this->analyze($test, 'tests/Unit/HelperTest.php'),
            'Documented limitation: the `<?php` marker is on an earlier physical line.'
        );
    }

    public function testPasswordComparisonInsideEmbeddedSourceIsNotReported(): void
    {
        $test = "<?php\nclass AuthTest extends TestCase {\n"
            . "    public function test_login() {\n"
            . "        \$src = \"<?php\\nif (\\\$creds['password'] == '!S3cretMaster2024#Admin') {\\n}\\n\";\n"
            . "    }\n}\n";

        self::assertSame([], $this->analyze($test, 'tests/Unit/AuthTest.php'));
    }
}
