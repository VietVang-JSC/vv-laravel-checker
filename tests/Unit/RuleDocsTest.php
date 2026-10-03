<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Result\RuleIds;

/**
 * Locks the README rule reference to the registry.
 *
 * `RuleIdsTest` covers registry ↔ analyzers. This covers registry ↔ docs, which
 * is where the remaining drift lived: the README documented 14 of 43 rules not
 * at all — including every OWASP rule except six — and listed two ids that have
 * never existed (`DISABLED_CSRF`, `LARAVEL_PITFALL`). A reader looking up what
 * `OWASP_OWNERSHIP_IDOR` means found nothing, and a reader configuring
 * `quality_gate.ignore` by a documented id would have typed a rule that never
 * fires.
 *
 * The table is parsed, not pattern-matched loosely: every row must start with a
 * backticked id that the registry knows, every registry id must appear exactly
 * once, and OWASP rows must carry the category the registry assigns.
 */
final class RuleDocsTest extends TestCase
{
    private const HEADING = '## Custom Analyzer Rules';

    private const OWASP_HEADING = '### OWASP (`analyzers/owasp`)';

    public function testEveryRegistryRuleIsDocumentedExactlyOnce(): void
    {
        $documented = $this->documentedRules();

        foreach (RuleIds::all() as $rule) {
            self::assertSame(
                1,
                $documented[$rule] ?? 0,
                $rule . ' must appear exactly once in the README rule tables. Missing: no row. '
                . 'Duplicated: more than one row.'
            );
        }
    }

    public function testReadmeDocumentsNoRuleTheRegistryDoesNotKnow(): void
    {
        $known = array_flip(RuleIds::all());

        foreach (array_keys($this->documentedRules()) as $documented) {
            self::assertArrayHasKey(
                $documented,
                $known,
                'README documents ' . $documented . ', which no analyzer can emit.'
            );
        }
    }

    public function testOwaspRowsCarryTheRegistryCategory(): void
    {
        $rows = $this->tableRows($this->section(self::OWASP_HEADING, '### Laravel (`analyzers/laravel`)'));

        foreach (RuleIds::owaspRules() as $rule) {
            $row = null;
            foreach ($rows as $candidate) {
                if (str_starts_with($candidate, '| `' . $rule . '`')) {
                    $row = $candidate;
                    break;
                }
            }

            self::assertNotNull($row, $rule . ' is missing from the OWASP table.');

            $category = RuleIds::owaspCategory($rule);
            self::assertIsString($category);
            [$code] = explode(' ', $category, 2);
            self::assertStringContainsString(
                $code,
                (string) $row,
                $rule . ' must document its OWASP category ' . $category . '.'
            );
        }
    }

    public function testEveryOwaspRuleIsInTheOwaspTable(): void
    {
        $rows = $this->tableRows($this->section(self::OWASP_HEADING, '### Laravel (`analyzers/laravel`)'));
        $documented = implode("\n", $rows);

        foreach (RuleIds::owaspRules() as $rule) {
            self::assertStringContainsString('`' . $rule . '`', $documented);
        }
    }

    public function testRuleSectionStatesItIsVerified(): void
    {
        self::assertStringContainsString(
            'RuleDocsTest',
            $this->section(self::HEADING, '### Confidence & Tiering'),
            'The rule tables must point at the test that keeps them honest.'
        );
    }

    /**
     * Rule id => number of table rows documenting it.
     *
     * @return array<string, int>
     */
    private function documentedRules(): array
    {
        $section = $this->section(self::HEADING, '### Confidence & Tiering');
        $counts = [];

        foreach ($this->tableRows($section) as $row) {
            if (preg_match('/^\|\s*`([A-Z][A-Z0-9_]*)`/', $row, $m) !== 1) {
                continue;
            }
            $counts[$m[1]] = ($counts[$m[1]] ?? 0) + 1;
        }

        // Grouped rows ("A / B") count once per id.
        foreach ($this->groupedRows($section) as $row) {
            if (preg_match_all('/`([A-Z][A-Z0-9_]*)`/', $row, $m) < 1) {
                continue;
            }
            foreach ($m[1] as $id) {
                if (str_starts_with($id, 'analyzers') || !RuleIds::isOwasp($id)) {
                    continue;
                }
                $counts[$id] = ($counts[$id] ?? 0) + 1;
            }
        }

        return $counts;
    }

    /**
     * Rows whose first cell lists several rule ids are valid documentation but
     * are not the canonical one-row-per-rule shape.
     *
     * @return list<string>
     */
    private function groupedRows(string $section): array
    {
        $rows = [];
        foreach ($this->tableRows($section) as $row) {
            if (preg_match('/^\|\s*`[A-Z][A-Z0-9_]*`\s*\/.*`/', $row) === 1) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    /**
     * @return list<string>
     */
    private function tableRows(string $section): array
    {
        $rows = [];
        foreach (explode("\n", $section) as $line) {
            $line = trim($line);
            if (str_starts_with($line, '| ') && !str_contains($line, '|---')) {
                $rows[] = $line;
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
        self::assertIsInt($end, 'README is missing the section that follows: ' . $to);

        return substr($readme, $start, $end - $start);
    }
}
