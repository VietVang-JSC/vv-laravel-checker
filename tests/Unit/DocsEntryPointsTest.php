<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Commands\QualityCheckCommand;
use Rampart\QualityChecker\Standalone\StandaloneRunner;

/**
 * Locks the README to both entry points.
 *
 * The package can be driven two ways — `php artisan quality:check` inside a
 * Laravel app, and `php bin/quality-check <target>` against any directory. The
 * documentation originally presented the second as a footnote under Quick Start
 * and listed every option in one undifferentiated table, so a reader could not
 * tell that `--fix`, `--ignore`, `--ci` and `--json` do not exist in standalone
 * mode, nor that `--path` means something different in each.
 *
 * Both facts are now asserted from the code rather than from prose: the Artisan
 * signature is reflected off the command class, and the standalone flag set is
 * read from the runner that parses it. A new option that is not documented, or
 * documented for the wrong entry point, fails the build.
 */
final class DocsEntryPointsTest extends TestCase
{
    private const HEADING = '## Two Ways to Run';

    private const OPTIONS = '## Options Reference';

    public function testBothEntryPointsArePresentedAsPeers(): void
    {
        $section = $this->section(self::HEADING, '## Quick Start (5 minutes)');

        self::assertStringContainsString('php artisan quality:check', $section);
        self::assertStringContainsString('php bin/quality-check', $section);
        self::assertStringContainsString('Two Ways to Run', $section);

        foreach (['Lives in', 'Config source', 'Reports go to', 'Default checkers'] as $row) {
            self::assertStringContainsString(
                $row,
                $section,
                'The comparison table must state ' . $row . ' for both entry points.'
            );
        }
    }

    public function testEveryArtisanOptionIsDocumented(): void
    {
        $table = $this->optionsTable();

        foreach ($this->artisanOptions() as $option) {
            self::assertArrayHasKey(
                $option,
                $table,
                'Artisan option ' . $option . ' is not in the Options Reference table.'
            );
        }
    }

    public function testEveryStandaloneOptionIsDocumented(): void
    {
        $table = $this->optionsTable();

        foreach ($this->standaloneOptions() as $option) {
            self::assertArrayHasKey(
                $option,
                $table,
                'Standalone option ' . $option . ' is not in the Options Reference table.'
            );
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('artisanOnlyOptions')]
    public function testArtisanOnlyOptionIsMarkedAsSuch(string $option): void
    {
        $row = $this->optionsTable()[$option] ?? '';

        self::assertStringContainsString(
            'Artisan',
            $row,
            $option . ' only exists on the Artisan command and the table must say so.'
        );
        self::assertStringNotContainsString(
            'both',
            $row,
            $option . ' is not a shared option; it cannot be marked as applying to both.'
        );
    }

    /**
     * @return list<array{string}>
     */
    public static function artisanOnlyOptions(): array
    {
        return [['--ignore'], ['--fix'], ['--json'], ['--ci'], ['--no-auto-install']];
    }

    public function testSharedOptionsAreMarkedAsBoth(): void
    {
        foreach (['--format', '--only', '--tier', '--fail-on', '--exclude-path', '--profile'] as $option) {
            $row = $this->optionsTable()[$option] ?? '';

            self::assertStringContainsString(
                'both',
                $row,
                $option . ' exists on both entry points and the table must say so.'
            );
        }
    }

    public function testPathOptionDocumentsItsDifferentMeanings(): void
    {
        $row = $this->optionsTable()['--path'] ?? '';

        self::assertStringContainsString('Artisan', $row);
        self::assertStringContainsString('Standalone', $row);
    }

    /**
     * Options declared on the Artisan command signature.
     *
     * @return list<string>
     */
    private function artisanOptions(): array
    {
        $signature = (new \ReflectionClass(QualityCheckCommand::class))
            ->getDefaultProperties()['signature'] ?? '';
        self::assertIsString($signature);

        preg_match_all('/\{(--[a-z0-9-]+)/', $signature, $m);

        $options = array_values(array_unique($m[1]));
        sort($options);

        return $options;
    }

    /**
     * Options the standalone runner parses, read from the class that parses
     * them so a new flag cannot slip past the docs.
     *
     * @return list<string>
     */
    private function standaloneOptions(): array
    {
        $source = (string) file_get_contents(
            dirname(__DIR__, 2) . '/src/Standalone/StandaloneRunner.php'
        );

        preg_match_all("/\\\$key === '([a-z0-9-]+)'/", $source, $m);
        $special = array_map(static fn (string $k): string => '--' . $k, $m[1]);

        preg_match_all("/\\\$this->options\['([a-z0-9-]+)'\]/", $source, $m2);
        $generic = array_map(static fn (string $k): string => '--' . $k, $m2[1]);

        $help = [];
        preg_match_all('/^.*\$output->writeln\(\'  (--[a-z0-9-]+)/m', $source, $m3);
        $help = array_merge($help, $m3[1]);

        $options = array_values(array_unique(array_merge($special, $generic, $help)));
        // Generic keys are stored without the leading dashes and include help-only
        // spellings; normalise and drop non-option keys.
        $options = array_values(array_filter($options, static fn (string $o): bool => str_starts_with($o, '--')));
        sort($options);

        return $options;
    }

    /**
     * @return array<string, string> option => its table row
     */
    private function optionsTable(): array
    {
        $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');
        $start = strpos($readme, self::OPTIONS);
        self::assertIsInt($start, 'README is missing the Options Reference section.');

        $end = strpos($readme, "\n## ", $start + strlen(self::OPTIONS));
        $section = $end === false ? substr($readme, $start) : substr($readme, $start, $end - $start);

        $rows = [];
        foreach (explode("\n", $section) as $line) {
            $line = trim($line);
            if (preg_match('/^\|\s*`?(-[a-z], )?(--[a-z0-9-]+|-\w)`?/', $line, $m) !== 1) {
                continue;
            }
            $rows[$m[2]] = $line;
            // `-q`, `--quiet` documents two options in one row.
            if (str_contains($line, '`--quiet`')) {
                $rows['--quiet'] = $line;
            }
            if (str_contains($line, '`-q`')) {
                $rows['-q'] = $line;
            }
        }

        return $rows;
    }

    private function section(string $from, string $to): string
    {
        $readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');
        $start = strpos($readme, $from);
        self::assertIsInt($start, 'README is missing the section: ' . $from);

        $end = strpos($readme, $to, $start + strlen($from));
        self::assertIsInt($end, 'README is missing the section: ' . $to);

        return substr($readme, $start, $end - $start);
    }
}
