<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\TrivyChecker;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;
use ReflectionMethod;

/**
 * Pins the `trivy --format json` contract this package depends on.
 *
 * `TrivyChecker::parseOutput()` is the only place the package reads Trivy's
 * output, and it had no test: the checker is disabled by default and needs
 * a real `trivy` binary, so the suite never ran the parser. A change in
 * Trivy's JSON shape would have degraded to "0 findings" — a silently
 * passing gate rather than a visible failure.
 *
 * Fixtures below are verbatim shapes from Trivy `0.74.0` (`trivy config`
 * and `trivy fs --format json`), captured from the docs and a real run:
 *  - `Results[].Target` is the scanned file / image layer
 *  - `Results[].Misconfigurations[]` carries `AVDID`/`ID`, `Title`/`Message`,
 *    `Severity`, and `CauseMetadata.StartLine`
 *  - `Results[].Secrets[]` carries `RuleID`, `Title`, `Severity`, `StartLine`
 *
 * Two details are easy to get wrong and are why fixtures are verbatim:
 *  - `AVDID` vs `ID` fallback: older output uses `ID`, current uses `AVDID`
 *  - `StartLine` is inside `CauseMetadata` for misconfigs but top-level for
 *    secrets; missing line must not crash and must become null-line.
 */
final class TrivyJsonContractTest extends TestCase
{
    /**
     * @return list<Issue>
     */
    private function parse(string $json): array
    {
        $method = new ReflectionMethod(TrivyChecker::class, 'parseOutput');
        $method->setAccessible(true);

        /** @var list<Issue> $issues */
        $issues = $method->invoke(new TrivyChecker(), $json);

        return $issues;
    }

    public function testParsesMisconfigurationsWithAvdidAndCauseLine(): void
    {
        $json = json_encode([
            'Results' => [
                [
                    'Target' => 'Dockerfile',
                    'Class' => 'config',
                    'Type' => 'dockerfile',
                    'Misconfigurations' => [
                        [
                            'ID' => 'AVD-DS-002',
                            'AVDID' => 'AVD-DS-002',
                            'Title' => 'Image user should not be \'root\'',
                            'Severity' => 'HIGH',
                            'CauseMetadata' => ['StartLine' => 5, 'EndLine' => 5],
                        ],
                        [
                            // older shape: ID only, no AVDID
                            'ID' => 'KSV014',
                            'Title' => 'Root file system is not read-only',
                            'Severity' => 'MEDIUM',
                            'CauseMetadata' => ['StartLine' => 12],
                        ],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertCount(2, $issues);
        self::assertSame('AVD-DS-002', $issues[0]->rule);
        self::assertSame('Dockerfile', $issues[0]->file);
        self::assertSame(5, $issues[0]->line);
        self::assertSame(Severity::Error, $issues[0]->severity); // HIGH -> Error
        self::assertSame('trivy', $issues[0]->source);
        self::assertSame('HIGH', $issues[0]->metadata['severity']);

        self::assertSame('KSV014', $issues[1]->rule);
        self::assertSame(12, $issues[1]->line);
        self::assertSame(Severity::Warning, $issues[1]->severity); // MEDIUM -> Warning
    }

    public function testParsesSecretsWithRuleIdAndStartLine(): void
    {
        $json = json_encode([
            'Results' => [
                [
                    'Target' => 'config/app.php',
                    'Class' => 'secret',
                    'Secrets' => [
                        [
                            'RuleID' => 'generic-secret',
                            'Category' => 'general',
                            'Title' => 'Generic Secret',
                            'Severity' => 'CRITICAL',
                            'StartLine' => 10,
                        ],
                        [
                            // missing RuleID fallback
                            'Title' => 'Sensitive information found',
                            'Severity' => 'HIGH',
                            'StartLine' => 0,
                        ],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertCount(2, $issues);
        self::assertSame('generic-secret', $issues[0]->rule);
        self::assertSame('config/app.php', $issues[0]->file);
        self::assertSame(10, $issues[0]->line);
        self::assertSame(Severity::Critical, $issues[0]->severity);
        self::assertSame('secret', $issues[0]->metadata['type']);

        self::assertSame('TRIVY_SECRET', $issues[1]->rule);
        self::assertNull($issues[1]->line, 'StartLine 0 must become null-line');
        self::assertSame(Severity::Error, $issues[1]->severity);
    }

    public function testParsesMixedMisconfigAndSecretInSameTarget(): void
    {
        $json = json_encode([
            'Results' => [
                [
                    'Target' => 'k8s/deployment.yaml',
                    'Misconfigurations' => [
                        ['AVDID' => 'AVD-KSV-001', 'Title' => 'Process can elevate its own privileges', 'Severity' => 'MEDIUM', 'CauseMetadata' => ['StartLine' => 7]],
                    ],
                    'Secrets' => [
                        ['RuleID' => 'aws-access-key', 'Title' => 'AWS Access Key', 'Severity' => 'CRITICAL', 'StartLine' => 15],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertCount(2, $issues);
        self::assertSame('AVD-KSV-001', $issues[0]->rule);
        self::assertSame('aws-access-key', $issues[1]->rule);
    }

    public function testSeverityMappingCoversAllLevels(): void
    {
        $json = json_encode([
            'Results' => [
                [
                    'Target' => 't',
                    'Misconfigurations' => [
                        ['AVDID' => 'A', 'Title' => 'c', 'Severity' => 'CRITICAL', 'CauseMetadata' => ['StartLine' => 1]],
                        ['AVDID' => 'B', 'Title' => 'c', 'Severity' => 'HIGH', 'CauseMetadata' => ['StartLine' => 2]],
                        ['AVDID' => 'C', 'Title' => 'c', 'Severity' => 'MEDIUM', 'CauseMetadata' => ['StartLine' => 3]],
                        ['AVDID' => 'D', 'Title' => 'c', 'Severity' => 'LOW', 'CauseMetadata' => ['StartLine' => 4]],
                        ['AVDID' => 'E', 'Title' => 'c', 'Severity' => 'UNKNOWN', 'CauseMetadata' => ['StartLine' => 5]],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertSame(Severity::Critical, $issues[0]->severity);
        self::assertSame(Severity::Error, $issues[1]->severity);
        self::assertSame(Severity::Warning, $issues[2]->severity);
        self::assertSame(Severity::Info, $issues[3]->severity);
        self::assertSame(Severity::Info, $issues[4]->severity);
    }

    public function testEmptyResultsProduceNoIssues(): void
    {
        $json = json_encode(['Results' => []], JSON_THROW_ON_ERROR);
        self::assertSame([], $this->parse($json));

        $json2 = json_encode(['Results' => [['Target' => 'Dockerfile']]], JSON_THROW_ON_ERROR);
        self::assertSame([], $this->parse($json2));
    }

    public function testMalformedOutputYieldsNoIssuesInsteadOfFailing(): void
    {
        self::assertSame([], $this->parse('not json at all'));
        self::assertSame([], $this->parse(''));
        self::assertSame([], $this->parse(json_encode(['Results' => 'not-an-array'], JSON_THROW_ON_ERROR)));
        self::assertSame([], $this->parse(json_encode(['Results' => [['Target' => 'x', 'Misconfigurations' => 'not-an-array']]], JSON_THROW_ON_ERROR)));
    }

    public function testRunIsSkippedWhenDisabled(): void
    {
        $ctx = new CheckContext(sys_get_temp_dir(), ['app'], [], sys_get_temp_dir() . '/r');
        // default config is enabled=false
        $checker = new TrivyChecker();
        $result = $checker->run($ctx);

        self::assertSame('skipped', $result->status);
        self::assertSame([], $result->issues);
        self::assertStringContainsString('disabled', strtolower($result->summary ?? ''));
    }

    public function testIsAvailableReturnsFalseWhenDisabled(): void
    {
        $ctx = new CheckContext(sys_get_temp_dir(), ['app'], [], sys_get_temp_dir() . '/r');
        $checker = new TrivyChecker();
        // default config is enabled=false, so isAvailable must be false
        // even without checking for a binary.
        self::assertFalse($checker->isAvailable($ctx));
        self::assertSame(['enabled' => false, 'mode' => 'config', 'binary' => 'trivy', 'version' => null], $checker->config());
    }
}
