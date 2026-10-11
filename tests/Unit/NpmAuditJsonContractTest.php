<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\NpmAuditChecker;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use ReflectionMethod;

/**
 * Pins the `npm audit --json` contract this package depends on.
 *
 * Same story as `TrivyJsonContractTest`: `NpmAuditChecker::parseOutput()`
 * is the only place the package reads npm's output, needs a real `npm`
 * binary + registry, so the suite never ran the parser. An npm shape
 * change would degrade to "0 findings" — a silently passing gate.
 *
 * Fixtures are the two real shapes:
 *  - npm v7+: `vulnerabilities: { pkg: { severity, via, range, ... } }`
 *  - npm v6: `advisories: { id: { module_name, severity, title } }`
 */
final class NpmAuditJsonContractTest extends TestCase
{
    /**
     * @return list<Issue>
     */
    private function parse(string $json): array
    {
        $method = new ReflectionMethod(NpmAuditChecker::class, 'parseOutput');
        $method->setAccessible(true);

        /** @var list<Issue> $issues */
        $issues = $method->invoke(new NpmAuditChecker(), $json);

        return $issues;
    }

    public function testParsesNpmV7Vulnerabilities(): void
    {
        $json = json_encode([
            'vulnerabilities' => [
                'lodash' => [
                    'name' => 'lodash',
                    'severity' => 'high',
                    'via' => [['name' => 'lodash', 'severity' => 'high', 'title' => 'Prototype Pollution']],
                    'range' => '<4.17.21',
                ],
            ],
        ]);
        $issues = $this->parse($json);
        self::assertCount(1, $issues);
        self::assertSame('NPM_AUDIT', $issues[0]->rule);
        self::assertSame(Severity::Error, $issues[0]->severity);
        self::assertStringContainsString('lodash', $issues[0]->message);
    }

    public function testMapsSeverityLevels(): void
    {
        $json = json_encode([
            'vulnerabilities' => [
                'a' => ['severity' => 'critical'],
                'b' => ['severity' => 'moderate'],
                'c' => ['severity' => 'low'],
                'd' => ['severity' => 'info'],
            ],
        ]);
        $issues = $this->parse($json);
        self::assertCount(4, $issues);
        self::assertSame(Severity::Critical, $issues[0]->severity);
        self::assertSame(Severity::Warning, $issues[1]->severity);
        self::assertSame(Severity::Info, $issues[2]->severity);
        self::assertSame(Severity::Info, $issues[3]->severity);
    }

    public function testParsesNpmV6AdvisoriesWithModuleName(): void
    {
        $json = json_encode([
            'advisories' => [
                '1065' => [
                    'module_name' => 'lodash',
                    'severity' => 'high',
                    'title' => 'Prototype Pollution',
                ],
            ],
        ]);
        $issues = $this->parse($json);
        self::assertCount(1, $issues);
        self::assertStringContainsString('lodash', $issues[0]->message);
        self::assertStringNotContainsString('1065', $issues[0]->message);
    }

    public function testEmptyAndInvalidJsonYieldNoIssues(): void
    {
        self::assertSame([], $this->parse(''));
        self::assertSame([], $this->parse('not json'));
        self::assertSame([], $this->parse('{"vulnerabilities":{}}'));
        self::assertSame([], $this->parse('{"vulnerabilities":{"x":"not-an-array"}}'));
    }

    public function testMissingSeverityDefaultsToWarning(): void
    {
        $issues = $this->parse(json_encode(['vulnerabilities' => ['leftpad' => ['via' => []]]]));
        self::assertCount(1, $issues);
        self::assertSame(Severity::Warning, $issues[0]->severity);
    }
}
