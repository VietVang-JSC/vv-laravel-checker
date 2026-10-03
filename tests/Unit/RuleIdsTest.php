<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Rampart\QualityChecker\Remediation\RuleRemediation;
use Rampart\QualityChecker\Result\RuleIds;

/**
 * RuleIds is the single registry reporters agree on, so it has to stay in sync
 * with the analyzers that define the rules and with the remediation catalog
 * that teaches the fix.
 *
 * The OWASP parity assertion is the important one: `JsonReporter::buildOwasp()`
 * skips any rule with no category, which silently under-reported
 * `OWASP_OWNERSHIP_IDOR` (0.6.x) and `OWASP_BLADE_DYNAMIC_INCLUDE` (0.7.0) —
 * findings existed in `checkers[].issues` but never reached `owasp.total`.
 * A new `OWASP_*` analyzer constant without a category now fails CI.
 */
final class RuleIdsTest extends TestCase
{
    /**
     * Every rule id declared as a `RULE*` constant by a src/Analyzers class,
     * found by reflection so new analyzers are picked up automatically.
     *
     * @return array<string, string> rule id => "Class::CONST"
     */
    private function rulesDeclaredByAnalyzers(): array
    {
        $analyzersRoot = dirname(__DIR__, 2) . '/src/Analyzers';
        $found = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($analyzersRoot, \FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            // Namespace mirrors the directory tree, so derive it from the path
            // rather than assuming a flat src/Analyzers layout.
            $relative = substr($file->getPathname(), strlen($analyzersRoot) + 1);
            $relative = str_replace(['/', '\\', '.php'], ['\\', '\\', ''], $relative);
            $class = 'Rampart\\QualityChecker\\Analyzers\\' . $relative;
            if (!class_exists($class)) {
                continue;
            }
            foreach ((new ReflectionClass($class))->getConstants() as $name => $value) {
                if (!is_string($value) || !str_starts_with($name, 'RULE')) {
                    continue;
                }
                if (!preg_match('/^[A-Z][A-Z0-9_]*$/', $value)) {
                    continue;
                }
                $found[$value] = $class . '::' . $name;
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * @return array<string, string> the OWASP subset, keyed by rule id
     */
    private function owaspRulesDeclaredByAnalyzers(): array
    {
        return array_filter(
            $this->rulesDeclaredByAnalyzers(),
            static fn (string $rule): bool => str_starts_with($rule, 'OWASP_'),
            ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * The registry must list every rule any analyzer can emit. A missing entry
     * means that rule silently loses its OWASP category, remediation entry and
     * quality-score dimension.
     */
    public function testEveryAnalyzerRuleIsRegistered(): void
    {
        $declared = $this->rulesDeclaredByAnalyzers();
        $registered = RuleIds::all();

        self::assertNotSame([], $declared, 'no analyzer rule constants discovered');

        $missing = array_diff_key($declared, array_flip($registered));
        self::assertSame(
            [],
            $missing,
            'rule ids emitted by an analyzer but absent from RuleIds::all(): '
                . implode(', ', array_map(
                    static fn (string $rule): string => $rule . ' (' . $declared[$rule] . ')',
                    $missing
                ))
        );
    }

    public function testRegistryHasNoRulesNoAnalyzerEmits(): void
    {
        $declared = $this->rulesDeclaredByAnalyzers();

        $phantom = array_diff(RuleIds::all(), array_keys($declared));
        self::assertSame(
            [],
            array_values($phantom),
            'rules registered that no analyzer declares: ' . implode(', ', $phantom)
        );
    }

    public function testEveryOwaspAnalyzerRuleHasACategory(): void
    {
        $declared = $this->owaspRulesDeclaredByAnalyzers();
        $categories = RuleIds::owaspCategories();

        self::assertNotSame([], $declared, 'no OWASP analyzer constants discovered');

        $missing = array_diff_key($declared, $categories);
        self::assertSame(
            [],
            $missing,
            'OWASP rules without a category are dropped from the JSON owasp block: '
                . implode(', ', $missing)
        );
    }

    public function testOwaspCategoryHasNoPhantomRules(): void
    {
        $declared = $this->owaspRulesDeclaredByAnalyzers();

        $phantom = array_diff_key(RuleIds::owaspCategories(), $declared);
        self::assertSame(
            [],
            $phantom,
            'categories for rules no analyzer can emit: ' . implode(', ', $phantom)
        );
    }

    public function testOwaspCategoriesAreLabelledAndShareable(): void
    {
        $categories = RuleIds::owaspCategories();

        // Categories are a rollup, so two rules may share a label (IDOR is a
        // subset of A01); rule ids themselves must stay unique.
        self::assertSame(
            count($categories),
            count(array_unique(array_keys($categories))),
            'duplicate OWASP rule id'
        );
        foreach ($categories as $rule => $label) {
            self::assertNotSame('', trim($label), $rule);
            self::assertMatchesRegularExpression('/^A\d\d /', $label, $rule);
        }
    }

    /**
     * Regression: these three shipped without a category and were dropped from
     * the JSON `owasp` block, so `owasp.total` under-reported real findings.
     */
    public function testPreviouslyUnmappedOwaspRulesAreNowCounted(): void
    {
        self::assertSame(
            'A01 Broken Access Control',
            RuleIds::owaspCategory(RuleIds::OWASP_OWNERSHIP_IDOR)
        );
        self::assertSame('A03 Injection (XSS)', RuleIds::owaspCategory(RuleIds::OWASP_BLADE_XSS));
        self::assertSame(
            'A01 Path Traversal',
            RuleIds::owaspCategory(RuleIds::OWASP_BLADE_DYNAMIC_INCLUDE)
        );
    }

    public function testCatalogCoversExactlyTheRegisteredRules(): void
    {
        $catalog = array_keys(RuleRemediation::all());
        $registered = RuleIds::all();

        sort($catalog);
        $sorted = $registered;
        sort($sorted);

        self::assertSame(
            $sorted,
            $catalog,
            'RuleIds::all() and RuleRemediation::all() must list the same rule ids'
        );
    }

    public function testAllReturnsEveryRuleExactlyOnce(): void
    {
        $all = RuleIds::all();

        self::assertSame($all, array_values(array_unique($all)), 'duplicate rule id in all()');
        foreach (RuleIds::owaspRules() as $owasp) {
            self::assertContains($owasp, $all, 'OWASP rule missing from all()');
        }
        foreach ($all as $rule) {
            self::assertMatchesRegularExpression('/^[A-Z][A-Z0-9_]*$/', $rule);
        }
    }

    public function testOwaspHelpers(): void
    {
        self::assertTrue(RuleIds::isOwasp(RuleIds::OWASP_SSRF));
        self::assertTrue(RuleIds::isOwasp('OWASP_NOT_YET_REGISTERED'));
        self::assertFalse(RuleIds::isOwasp(RuleIds::SQL_INJECTION));
        self::assertSame('A10 SSRF', RuleIds::owaspCategory(RuleIds::OWASP_SSRF));
        self::assertNull(RuleIds::owaspCategory(RuleIds::SQL_INJECTION));
        self::assertNull(RuleIds::owaspCategory('NO_SUCH_RULE'));
        // An unmapped OWASP rule is still OWASP, just not categorised yet —
        // RuleIdsTest::testEveryOwaspAnalyzerRuleHasACategory is what forces
        // the category to exist for anything an analyzer can actually emit.
        self::assertNull(RuleIds::owaspCategory('OWASP_NOT_YET_REGISTERED'));
    }
}
