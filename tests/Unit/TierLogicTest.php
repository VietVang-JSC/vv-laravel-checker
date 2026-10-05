<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\CustomAnalyzerChecker;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Runner\CheckRunner;

final class TierLogicTest extends TestCase
{
    private function issue(Severity $severity, Confidence $confidence, string $source = 'custom'): Issue
    {
        return new Issue('R', 'm', 'f.php', 1, $severity, $source, [], $confidence);
    }

    private function context(string $tier, string $minConf = 'low', string $failOn = 'error'): CheckContext
    {
        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            sys_get_temp_dir() . '/r',
            tier: $tier,
            minConfidence: $minConf,
            failOn: $failOn,
        );
    }

    public function testSecurityTierIgnoresLowConfidenceIssue(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Critical, Confidence::Low),
        ], null, null);

        self::assertFalse($runner->shouldFail([$result]));
    }

    public function testSecurityTierFailsOnHighConfidenceSecurityIssue(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::High),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }

    public function testQualityTierFailsOnMediumConfidenceError(): void
    {
        $runner = new CheckRunner($this->context('quality'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::Medium),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }

    public function testMinConfidenceHighFiltersMedium(): void
    {
        $runner = new CheckRunner($this->context('quality', 'high'));
        $result = new CheckResult('custom', 'failed', 0.1, [
            $this->issue(Severity::Critical, Confidence::Medium),
        ], null, null);

        self::assertFalse($runner->shouldFail([$result]));
    }

    public function testSecurityTierAlwaysCountsComposerAudit(): void
    {
        $runner = new CheckRunner($this->context('security'));
        $result = new CheckResult('composer_audit', 'failed', 0.1, [
            $this->issue(Severity::Error, Confidence::Medium, 'composer_audit'),
        ], null, null);

        self::assertTrue($runner->shouldFail([$result]));
    }

    /**
     * Blade is demoted to 'info' in the shipped config because it dominates
     * finding counts on real projects. Reflected XSS — `{!! request('x') !!}` —
     * is real, so the demotion must not make the security gate pass silently:
     * this asserts the exact consequence, so nobody has to infer it.
     */
    public function testBladeRequestXssIsReportedAtInfoAndDoesNotFailSecurityTier(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-blade-' . uniqid('', true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views', 0777, true);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'x.blade.php',
            "<div>{!! request('q') !!}</div>\n"
        );

        try {
            $runner = new CheckRunner($this->context('security'));
            $result = (new CustomAnalyzerChecker())->run(new CheckContext(
                $dir,
                ['resources'],
                ['analyzers' => ['owasp' => ['blade_xss' => true], 'severity_overrides' => [
                    'OWASP_BLADE_XSS' => 'info',
                    'OWASP_BLADE_DYNAMIC_INCLUDE' => 'info',
                ]]],
                $dir . '/out',
                tier: 'security',
            ));

            $blade = array_values(array_filter(
                $result->issues,
                static fn (Issue $i): bool => $i->rule === 'OWASP_BLADE_XSS'
            ));

            self::assertCount(1, $blade, 'The fixture is reflected XSS and must still be reported.');
            self::assertSame(Severity::Info, $blade[0]->severity);
            self::assertFalse(
                $runner->shouldFail([$result]),
                'At info severity the security tier no longer fails on reflected XSS.'
            );
        } finally {
            @unlink($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'x.blade.php');
            @rmdir($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views');
            @rmdir($dir . DIRECTORY_SEPARATOR . 'resources');
            @rmdir($dir);
        }
    }

    /**
     * The escape hatch: a project that wants blade to fail the gate restores the
     * severity, and the finding is then gated again.
     */
    public function testBladeSeverityCanBeRestoredToError(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-blade2-' . uniqid('', true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views', 0777, true);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'x.blade.php',
            "<div>{!! request('q') !!}</div>\n"
        );

        try {
            $runner = new CheckRunner($this->context('security'));
            $result = (new CustomAnalyzerChecker())->run(new CheckContext(
                $dir,
                ['resources'],
                ['analyzers' => ['owasp' => ['blade_xss' => true], 'severity_overrides' => [
                    'OWASP_BLADE_XSS' => 'error',
                ]]],
                $dir . '/out',
                tier: 'security',
            ));

            self::assertTrue(
                $runner->shouldFail([$result]),
                'Restoring the severity must restore the gate failure.'
            );
        } finally {
            @unlink($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'x.blade.php');
            @rmdir($dir . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views');
            @rmdir($dir . DIRECTORY_SEPARATOR . 'resources');
            @rmdir($dir);
        }
    }

    /**
     * The analyzers filtered on config['min_confidence'] while the gate filtered
     * on the resolved $ctx->minConfidence. With the two out of step, `--min-
     * confidence=high` printed low-confidence findings that the same run then
     * declined to fail on — the report and the gate disagreed.
     */
    public function testAnalyzerFilteringFollowsTheResolvedConfidence(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-conf-' . uniqid('', true);
        @mkdir($dir, 0777, true);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'Todo.php',
            "<?php\nnamespace App;\nclass Todo {\n    public function run(): void {\n        // TODO: finish this\n    }\n}\n"
        );

        try {
            $checker = new CustomAnalyzerChecker();
            $low = new CheckContext(
                $dir,
                ['Todo.php'],
                ['analyzers' => ['convention' => ['todo_fixme' => true]], 'min_confidence' => 'high'],
                $dir . '/out',
                minConfidence: 'low',
            );
            $high = new CheckContext(
                $dir,
                ['Todo.php'],
                ['analyzers' => ['convention' => ['todo_fixme' => true]], 'min_confidence' => 'high'],
                $dir . '/out',
                minConfidence: 'high',
            );

            $lowConfidence = $checker->run($low)->issues;
            $highConfidence = $checker->run($high)->issues;

            self::assertNotSame([], $lowConfidence, 'The low-confidence run found nothing to filter.');
            self::assertSame([], $highConfidence, 'min-confidence=high still listed low-confidence findings.');
        } finally {
            @unlink($dir . DIRECTORY_SEPARATOR . 'Todo.php');
            @rmdir($dir);
        }
    }
}
