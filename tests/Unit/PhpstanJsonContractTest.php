<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\PhpstanChecker;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use ReflectionMethod;

/**
 * Pins the `phpstan --error-format=json` contract this package depends on.
 *
 * `PhpstanChecker::parseOutput()` is the only place the package reads PHPStan's
 * output, and it had no test: the checker skips itself unless the *target* has
 * `vendor/bin/phpstan`, so the suite never ran the parser, and a change in
 * PHPStan's JSON shape would have degraded to "0 findings" — a silently passing
 * gate rather than a visible failure.
 *
 * The fixtures below are verbatim output from PHPStan 2.0 (`phpstan/phpstan:2.0`),
 * captured by running the analyser against a file that instantiates a
 * non-existent class and passes it to `strlen()`:
 *
 *     vendor/bin/phpstan analyse Sample.php --error-format=json --no-progress --level=5
 *
 * Two details here are easy to get wrong and are the reason the fixtures are
 * verbatim rather than invented:
 *
 *  - `identifier` is the rule id (`class.notFound`, `argument.type`) and is what
 *    this package surfaces as the issue rule, so it has to survive parsing. PHPStan
 *    2.x renamed identifiers from numeric ids; the `?? 'PHPSTAN'` fallback exists
 *    for older output and must not be what a current run produces.
 *  - `line` is nullable. A file-level diagnostic — an unmatched `ignoreErrors`
 *    pattern, for instance — arrives with `"line": null`, which must become a
 *    `null`-line issue rather than being dropped or coerced to 0.
 */
final class PhpstanJsonContractTest extends TestCase
{
    /**
     * @return list<Issue>
     */
    private function parse(string $json): array
    {
        $method = new ReflectionMethod(PhpstanChecker::class, 'parseOutput');
        $method->setAccessible(true);

        /** @var list<Issue> $issues */
        $issues = $method->invoke(new PhpstanChecker(), $json);

        return $issues;
    }

    public function testParsesFileDiagnostics(): void
    {
        // Verbatim PHPStan 2.0 output; paths and backslashes escaped as JSON.
        $json = json_encode([
            'totals' => ['errors' => 0, 'file_errors' => 2],
            'files' => [
                'C:\\app\\Sample.php' => [
                    'errors' => 2,
                    'messages' => [
                        [
                            'message' => 'Instantiated class App\\Contracts\\MissingContract not found.',
                            'line' => 13,
                            'ignorable' => true,
                            'tip' => 'Learn more at https://phpstan.org/user-guide/discovering-symbols',
                            'identifier' => 'class.notFound',
                        ],
                        [
                            'message' => 'Parameter #1 $string of function strlen expects string, App\\Contracts\\MissingContract given.',
                            'line' => 15,
                            'ignorable' => true,
                            'identifier' => 'argument.type',
                        ],
                    ],
                ],
            ],
            'errors' => [],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertCount(2, $issues);
        self::assertSame(
            ['class.notFound', 'argument.type'],
            array_map(static fn (Issue $issue): string => $issue->rule, $issues)
        );
        self::assertSame('C:\\app\\Sample.php', $issues[0]->file);
        self::assertSame(13, $issues[0]->line);
        self::assertSame(15, $issues[1]->line);
        self::assertSame(Severity::Error, $issues[0]->severity);
        self::assertSame('phpstan', $issues[0]->source);
        self::assertSame(['ignorable' => true], $issues[0]->metadata);
        self::assertSame('Instantiated class App\\Contracts\\MissingContract not found.', $issues[0]->message);
    }

    public function testFileLevelDiagnosticWithoutALineKeepsANullLine(): void
    {
        // Verbatim PHPStan 2.0 output for an `ignoreErrors` pattern that matched
        // nothing — note `"line": null` and `identifier: ignore.unmatched`.
        $json = json_encode([
            'totals' => ['errors' => 0, 'file_errors' => 1],
            'files' => [
                'C:\\app\\Clean.php' => [
                    'errors' => 1,
                    'messages' => [[
                        'message' => 'Ignored error pattern #^This pattern will never match anything\\.$# in path C:\\app\\Clean.php was not matched in reported errors.',
                        'line' => null,
                        'ignorable' => false,
                        'identifier' => 'ignore.unmatched',
                    ]],
                ],
            ],
            'errors' => [],
        ], JSON_THROW_ON_ERROR);

        $issues = $this->parse($json);

        self::assertCount(1, $issues);
        self::assertSame('ignore.unmatched', $issues[0]->rule);
        self::assertNull($issues[0]->line, 'a file-level diagnostic must not be coerced to line 0');
        self::assertSame('C:\\app\\Clean.php', $issues[0]->file);
        self::assertSame(['ignorable' => false], $issues[0]->metadata);
    }

    public function testAMessageWithoutAnIdentifierFallsBackToPhpstan(): void
    {
        // PHPStan 1.x emitted numeric identifiers and, for some internal
        // diagnostics, none at all. The fallback keeps those reportable.
        $issues = $this->parse(json_encode([
            'files' => [
                '/app/A.php' => [
                    'messages' => [['message' => 'Something went wrong', 'line' => 3]],
                ],
            ],
        ], JSON_THROW_ON_ERROR));

        self::assertCount(1, $issues);
        self::assertSame('PHPSTAN', $issues[0]->rule);
        self::assertSame(3, $issues[0]->line);
    }

    public function testTopLevelErrorsBecomeIssuesWithoutAFile(): void
    {
        // Shape of PHPStan's JSON formatter for errors that are not attached to
        // a file (an internal error, a bad configuration). Not captured from a
        // run here because provoking a PHPStan internal error is not
        // reproducible in a test; the `files` fixtures above are verbatim.
        $issues = $this->parse(json_encode([
            'totals' => ['errors' => 1, 'file_errors' => 0],
            'files' => [],
            'errors' => ['Internal error: something went wrong'],
        ], JSON_THROW_ON_ERROR));

        self::assertCount(1, $issues);
        self::assertSame('PHPSTAN_ERROR', $issues[0]->rule);
        self::assertSame('Internal error: something went wrong', $issues[0]->message);
        self::assertNull($issues[0]->file);
        self::assertNull($issues[0]->line);
    }

    public function testEmptyErrorStringsAreIgnored(): void
    {
        $issues = $this->parse(json_encode([
            'files' => [],
            'errors' => ['', '   '],
        ], JSON_THROW_ON_ERROR));

        self::assertSame([], $issues);
    }

    public function testCleanRunProducesNoIssues(): void
    {
        $json = json_encode([
            'totals' => ['errors' => 0, 'file_errors' => 0],
            'files' => ['C:\\app\\Clean.php' => ['errors' => 0, 'messages' => []]],
            'errors' => [],
        ], JSON_THROW_ON_ERROR);

        self::assertSame([], $this->parse($json));
    }

    public function testMalformedOutputYieldsNoIssuesInsteadOfFailing(): void
    {
        // PHPStan writes plain text ("Path ... does not exist") instead of JSON
        // when it fails before the formatter runs, and the checker must not treat
        // that as a clean pass with invented findings.
        self::assertSame([], $this->parse('Path /app/Missing.php does not exist'));
        self::assertSame([], $this->parse(''));
        self::assertSame([], $this->parse(json_encode([
            'files' => ['/app/A.php' => 'not-an-array'],
        ], JSON_THROW_ON_ERROR)));
        self::assertSame([], $this->parse(json_encode([
            'files' => ['/app/A.php' => ['messages' => ['not-an-array']]],
        ], JSON_THROW_ON_ERROR)));
    }
}
