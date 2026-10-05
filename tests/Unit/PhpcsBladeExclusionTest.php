<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\PhpcsChecker;
use Rampart\QualityChecker\Runner\CheckContext;
use ReflectionMethod;

/**
 * The blade exclusion phpcs needs, and the escape hatch for a project that wants
 * templates linted anyway.
 *
 * phpcs has no extension filter, so a scan path containing `resources/views`
 * makes it report every template as `Internal.NoCodeFound` and
 * `Internal.LineEndings.Mixed`. On any Laravel app that is noise on every file
 * under `resources/views`, produced on the very first run — the fastest way to
 * teach a developer that the output is not worth reading.
 *
 * The command is asserted through reflection because the checker skips itself
 * unless the *target* project has `vendor/bin/phpcs`, so building a command for
 * a real target is not something a unit test can do cheaply. The contract under
 * test is the argv, and argv is what the behavior depends on.
 */
final class PhpcsBladeExclusionTest extends TestCase
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
     * @param array<string, mixed> $config
     * @return list<string>
     */
    private function command(array $config = []): array
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-phpcs-blade-' . uniqid('', true);
        @mkdir($this->dir, 0777, true);

        $ctx = new CheckContext(
            $this->dir,
            ['app', 'resources'],
            [],
            $this->dir . '/out',
        );

        $method = new ReflectionMethod(PhpcsChecker::class, 'buildCommand');

        /** @var list<string> $command */
        $command = $method->invoke(new PhpcsChecker(), 'phpcs', $ctx, (string) ($config['standard'] ?? 'PSR12'), $config);

        return $command;
    }

    public function testBladeTemplatesAreExcludedByDefault(): void
    {
        $command = $this->command();

        self::assertContains(
            '--ignore=*.blade.php',
            $command,
            'phpcs must not lint blade templates: they are not PHP.'
        );
    }

    /**
     * A project's own ignores survive. Replacing them would be a worse bug than
     * the noise being fixed: a team that excluded generated code would silently
     * start seeing it again.
     */
    public function testProjectIgnoresAreAppendedNotReplaced(): void
    {
        $command = $this->command(['ignore' => ['*/generated/*', '*.inc']]);

        self::assertContains('--ignore=*.blade.php', $command);
        self::assertContains('--ignore=*/generated/*', $command);
        self::assertContains('--ignore=*.inc', $command);
    }

    public function testStringIgnoreIsAccepted(): void
    {
        $command = $this->command(['ignore' => '*/vendor/*']);

        self::assertContains('--ignore=*/vendor/*', $command);
        self::assertContains('--ignore=*.blade.php', $command);
    }

    /**
     * @param array<string, mixed> $config
     * @return list<string>
     */
    private function ignores(array $config): array
    {
        $method = new ReflectionMethod(PhpcsChecker::class, 'configuredIgnores');

        /** @var list<string> $ignores */
        $ignores = $method->invoke(new PhpcsChecker(), $config);

        return $ignores;
    }

    public function testIgnoreIsOptionalAndFiltersNonStrings(): void
    {
        self::assertSame([], $this->ignores([]));
        self::assertSame([], $this->ignores(['ignore' => null]));
        self::assertSame(['*.inc'], $this->ignores(['ignore' => ['*.inc', 42, null]]));
    }

    public function testScanPathsStillIncludeResourcesForTheBladeAnalyzer(): void
    {
        // The exclusion must live in the checker, not by dropping `resources`
        // from the scan paths: CustomAnalyzerChecker collects blade separately
        // and needs the path. Removing it would silence OWASP_BLADE_XSS.
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-phpcs-blade-' . uniqid('', true);
        @mkdir($this->dir . DIRECTORY_SEPARATOR . 'app', 0777, true);
        @mkdir($this->dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views', 0777, true);

        $runner = new \Rampart\QualityChecker\Standalone\StandaloneRunner([]);
        $method = new ReflectionMethod($runner, 'scanPaths');

        /** @var list<string> $paths */
        $paths = $method->invoke($runner, $this->dir);

        self::assertContains('resources', $paths, 'Blade must stay in the scan paths for the custom analyzers.');
    }
}
