<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Reporters\IssueGrouper;
use Rampart\QualityChecker\Reporters\JsonReporter;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\RuleIds;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

/**
 * Regression cover for the JSON `owasp` block under-counting real findings.
 *
 * `JsonReporter::buildOwasp()` used a hand-maintained rule => category map.
 * `OWASP_OWNERSHIP_IDOR` (0.6.x) and `OWASP_BLADE_DYNAMIC_INCLUDE` (0.7.0) were
 * added without an entry, and any unmapped rule was skipped outright — so those
 * findings appeared in `checkers[].issues` but never reached `owasp.categories`
 * or `owasp.total`. The map now lives in `RuleIds`, and these tests fail if a
 * single OWASP rule can slip through unmapped again.
 */
final class JsonOwaspReportTest extends TestCase
{
    private string $tempDir = '';

    protected function tearDown(): void
    {
        if ($this->tempDir !== '' && is_dir($this->tempDir)) {
            foreach (glob($this->tempDir . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
                @unlink((string) $file);
            }
            @rmdir($this->tempDir);
        }
        $this->tempDir = '';
    }

    private function context(): CheckContext
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-owasp-' . uniqid('', true);
        @mkdir($this->tempDir, 0777, true);

        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            $this->tempDir,
            packageVersion: '0.7.0'
        );
    }

    /**
     * @param list<string> $rules
     * @return array<string, mixed>
     */
    private function renderOwaspBlock(array $rules): array
    {
        $issues = [];
        foreach ($rules as $index => $rule) {
            $issues[] = new Issue(
                $rule,
                'Finding for ' . $rule,
                'app/Services/Target' . $index . '.php',
                10 + $index,
                Severity::Error,
                'custom',
                [],
                Confidence::High
            );
        }

        $results = [
            new CheckResult('custom', 'failed', 0.5, $issues, null, count($issues) . ' issues'),
        ];

        (new JsonReporter())->render($results, $this->context());

        $payload = json_decode(
            (string) file_get_contents($this->tempDir . DIRECTORY_SEPARATOR . 'quality-report.json'),
            true
        );
        self::assertIsArray($payload);

        return $payload['owasp'];
    }

    public function testEveryOwaspRuleLandsInTheOwaspBlock(): void
    {
        $rules = RuleIds::owaspRules();
        $block = $this->renderOwaspBlock($rules);

        self::assertSame(
            count($rules),
            $block['total'],
            'owasp.total must count every OWASP finding'
        );
    }

    /**
     * The three rules that shipped unmapped.
     */
    public function testPreviouslyUnmappedRulesAreCounted(): void
    {
        $block = $this->renderOwaspBlock([
            RuleIds::OWASP_OWNERSHIP_IDOR,
            RuleIds::OWASP_BLADE_XSS,
            RuleIds::OWASP_BLADE_DYNAMIC_INCLUDE,
        ]);

        self::assertSame(3, $block['total']);
        self::assertSame(1, $block['categories']['A01 Broken Access Control'] ?? null);
        self::assertSame(1, $block['categories']['A03 Injection (XSS)'] ?? null);
        self::assertSame(1, $block['categories']['A01 Path Traversal'] ?? null);
    }

    public function testSharedCategoriesAggregate(): void
    {
        $block = $this->renderOwaspBlock([
            RuleIds::OWASP_BROKEN_ACCESS_CONTROL,
            RuleIds::OWASP_OWNERSHIP_IDOR,
        ]);

        self::assertSame(2, $block['total']);
        self::assertSame(['A01 Broken Access Control' => 2], $block['categories']);
    }

    public function testNonOwaspRulesAreNotCounted(): void
    {
        $block = $this->renderOwaspBlock([
            RuleIds::SQL_INJECTION,
            RuleIds::MASS_ASSIGNMENT,
            RuleIds::MISSING_CONTROLLER_TEST,
        ]);

        self::assertSame(0, $block['total']);
        self::assertSame([], $block['categories']);
    }

    public function testMixedReportCountsOnlyOwasp(): void
    {
        $block = $this->renderOwaspBlock([
            RuleIds::OWASP_SSRF,
            RuleIds::OWASP_XXE,
            RuleIds::SQL_INJECTION,
        ]);

        self::assertSame(2, $block['total']);
        self::assertSame(1, $block['categories']['A10 SSRF'] ?? null);
        self::assertSame(1, $block['categories']['A05 XXE'] ?? null);
    }

    /**
     * The per-rule OWASP breakdown uses the same registry, so it must agree
     * with the category totals.
     */
    public function testIssueGrouperAgreesWithCategoryTotals(): void
    {
        $rules = RuleIds::owaspRules();
        $issues = [];
        foreach ($rules as $index => $rule) {
            $issues[] = new Issue(
                $rule,
                'Finding for ' . $rule,
                'app/Services/Target' . $index . '.php',
                10 + $index,
                Severity::Error,
                'custom',
                [],
                Confidence::High
            );
        }
        $results = [new CheckResult('custom', 'failed', 0.5, $issues, null, '')];
        $block = $this->renderOwaspBlock($rules);

        self::assertSame($rules, array_keys(IssueGrouper::owaspByRule($results)));
        self::assertSame(count($rules), array_sum($block['categories']));
    }
}
