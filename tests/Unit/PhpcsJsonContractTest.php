<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Result\Issue;
use ReflectionMethod;

/**
 * Pins the `phpcs --report=json` contract this package depends on.
 *
 * `PhpcsChecker::parseOutput()` is the only place the package touches phpcs
 * output, and it is invisible to the suite otherwise: the checker skips itself
 * unless the *target* has `vendor/bin/phpcs`, so no test ever ran the parser.
 * That is how the tool could ship with an unverified assumption about a
 * dependency it shells out to — and phpcs 4 is a major version away.
 *
 * Both fixtures below are real output, captured from the versions named:
 * 3.13 reports `PSR12.*` codes, 4.0 additionally reports `Squiz.*` ones from its
 * re-implemented PSR12 ruleset. The shape is identical; only the codes differ.
 * If a future phpcs changes the shape, these fixtures pin the expectation and
 * the failure lands here instead of in a consumer's build.
 */
final class PhpcsJsonContractTest extends TestCase
{
    /**
     * @return list<Issue>
     */
    private function parse(string $json, int $threshold = 0): array
    {
        $method = new ReflectionMethod(\Rampart\QualityChecker\Checkers\PhpcsChecker::class, 'parseOutput');
        $method->setAccessible(true);

        $checker = new \Rampart\QualityChecker\Checkers\PhpcsChecker();

        /** @var list<Issue> $issues */
        $issues = $method->invoke($checker, $json, $threshold);

        return $issues;
    }

    public function testParsesPhpcs3Output(): void
    {
        $json = json_encode([
            'totals' => ['errors' => 1, 'warnings' => 0, 'fixable' => 1],
            'files' => [
                '/app/Http/Controllers/UserController.php' => [
                    'errors' => 1,
                    'warnings' => 0,
                    'messages' => [[
                        'message' => 'Expected 1 newline at end of file; 0 found',
                        'source' => 'PSR2.Files.EndFileNewline.NoneFound',
                        'severity' => 5,
                        'fixable' => true,
                        'type' => 'ERROR',
                        'line' => 42,
                        'column' => 1,
                    ]],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse((string) $json);

        self::assertCount(1, $issues);
        self::assertSame('PSR2.Files.EndFileNewline.NoneFound', $issues[0]->rule);
        self::assertSame('/app/Http/Controllers/UserController.php', $issues[0]->file);
        self::assertSame(42, $issues[0]->line);
        self::assertSame(\Rampart\QualityChecker\Result\Severity::Error, $issues[0]->severity);
        self::assertSame('phpcs', $issues[0]->source);
    }

    public function testParsesPhpcs4OutputIncludingItsExtraSquizCodes(): void
    {
        // Verbatim shape from PHP_CodeSniffer 4.0.0 with --standard=PSR12: the
        // re-implemented ruleset emits Squiz.* codes that 3.x did not.
        $json = json_encode([
            'totals' => ['errors' => 2, 'warnings' => 1, 'fixable' => 2],
            'files' => [
                'C:\\app\\Http\\Controllers\\DemoController.php' => [
                    'errors' => 2,
                    'warnings' => 1,
                    'messages' => [
                        [
                            'message' => 'Opening brace should be on a new line',
                            'source' => 'Squiz.Functions.MultiLineFunctionDeclaration.BraceOnSameLine',
                            'severity' => 5,
                            'fixable' => true,
                            'type' => 'ERROR',
                            'line' => 4,
                            'column' => 34,
                        ],
                        [
                            'message' => 'Line exceeds 120 characters',
                            'source' => 'Generic.Files.LineLength.TooLong',
                            'severity' => 5,
                            'fixable' => false,
                            'type' => 'WARNING',
                            'line' => 9,
                            'column' => 121,
                        ],
                        [
                            'message' => 'Class must be final or abstract',
                            'source' => 'PSR1.Classes.ClassDeclaration.AbstractOrFinal',
                            'severity' => 3,
                            'fixable' => true,
                            'type' => 'ERROR',
                            'line' => 3,
                            'column' => 1,
                        ],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse((string) $json);

        self::assertCount(3, $issues);
        self::assertSame(
            [
                'Squiz.Functions.MultiLineFunctionDeclaration.BraceOnSameLine',
                'Generic.Files.LineLength.TooLong',
                'PSR1.Classes.ClassDeclaration.AbstractOrFinal',
            ],
            array_map(static fn ($issue): string => $issue->rule, $issues)
        );
        self::assertSame(\Rampart\QualityChecker\Result\Severity::Warning, $issues[1]->severity);
        self::assertSame(\Rampart\QualityChecker\Result\Severity::Error, $issues[2]->severity);
        self::assertSame('C:\\app\\Http\\Controllers\\DemoController.php', $issues[0]->file);
    }

    public function testSeverityThresholdFiltersByPhpcsSeverity(): void
    {
        $json = json_encode([
            'totals' => ['errors' => 1, 'warnings' => 1],
            'files' => [
                '/app/A.php' => [
                    'messages' => [
                        ['message' => 'notice', 'source' => 'S.X', 'severity' => 3, 'type' => 'ERROR', 'line' => 1],
                        ['message' => 'warning', 'source' => 'S.Y', 'severity' => 5, 'type' => 'WARNING', 'line' => 2],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse((string) $json, 5);

        self::assertCount(1, $issues);
        self::assertSame('S.Y', $issues[0]->rule);
    }

    public function testMalformedOutputYieldsNoIssuesInsteadOfFailing(): void
    {
        self::assertSame([], $this->parse('not json at all'));
        self::assertSame([], $this->parse(json_encode(['totals' => ['errors' => 0]], JSON_THROW_ON_ERROR)));
        self::assertSame([], $this->parse(json_encode([
            'files' => ['/app/A.php' => 'not-an-array'],
        ], JSON_THROW_ON_ERROR)));
        self::assertSame([], $this->parse(json_encode([
            'files' => ['/app/A.php' => ['messages' => ['not-an-array']]],
        ], JSON_THROW_ON_ERROR)));
    }

    public function testMessageWithoutLineIsTolerated(): void
    {
        $issues = $this->parse(json_encode([
            'files' => [
                '/app/A.php' => [
                    'messages' => [['message' => 'file level', 'source' => 'S.File', 'severity' => 5, 'type' => 'ERROR']],
                ],
            ],
        ], JSON_THROW_ON_ERROR));

        self::assertCount(1, $issues);
        self::assertNull($issues[0]->line);
    }
}
