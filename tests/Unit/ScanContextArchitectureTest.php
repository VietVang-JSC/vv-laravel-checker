<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * PERF-OPT-1 architecture guard: every analyzer under src/Analyzers/**
 * must read source/AST through ScanContext (sharedSource/sharedAst),
 * never through its own ParserFactory / parse() / file_get_contents().
 *
 * Allowlist (documented, not migrated):
 * - Analyzers/Security/Taint/TaintEngine.php: separate interprocedural
 *   engine, off by default, with its own injectable parser.
 *
 * Token-based (not regex) so sink-name string literals such as
 * 'file_get_contents' in PATH_TRAVERSAL/Ssrf sink lists do not trip it.
 */
final class ScanContextArchitectureTest extends TestCase
{
    /** @var list<string> paths relative to src/Analyzers/ */
    private const ALLOWLIST = [
        'Security/Taint/TaintEngine.php',
    ];

    public function testNoAnalyzerParsesOrReadsFilesDirectly(): void
    {
        $root = dirname(__DIR__, 2) . '/src/Analyzers';
        $violations = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($file->getPathname(), strlen($root) + 1);
            $relative = str_replace(DIRECTORY_SEPARATOR, '/', $relative);
            if (in_array($relative, self::ALLOWLIST, true)) {
                continue;
            }
            foreach ($this->violationsIn($file->getPathname(), true) as $violation) {
                $violations[] = $relative . $violation;
            }
        }

        self::assertSame(
            [],
            $violations,
            'Direct parse/IO in analyzers (use sharedSource/sharedAst instead)'
        );
    }

    /**
     * PERF-OPT-2 parser ownership: ScanContext is the single owner of
     * normal application-source parsing across ALL of src/ (analyzers,
     * semantic indexes, analysis helpers). Anything constructing its
     * own ParserFactory / calling ->parse() / building an AstPool
     * outside the named allowlist fails CI — including future
     * semantic consumers. Named exceptions only:
     * - Scanning/ScanContext.php: the owner itself.
     * - Analyzers/Security/Taint/TaintEngine.php: explicit independent
     *   engine, off by default, injectable parser.
     *
     * @var list<string> paths relative to src/
     */
    private const PARSER_OWNER_ALLOWLIST = [
        'Scanning/ScanContext.php',
        'Analyzers/Security/Taint/TaintEngine.php',
    ];

    public function testParserOwnershipAcrossSrc(): void
    {
        $root = dirname(__DIR__, 2) . '/src';
        $violations = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($file->getPathname(), strlen($root) + 1);
            $relative = str_replace(DIRECTORY_SEPARATOR, '/', $relative);
            if (in_array($relative, self::PARSER_OWNER_ALLOWLIST, true)) {
                continue;
            }
            foreach ($this->violationsIn($file->getPathname(), false) as $violation) {
                $violations[] = $relative . $violation;
            }
        }

        self::assertSame(
            [],
            $violations,
            'Private parsing outside ScanContext ownership (inject/share the canonical AST instead)'
        );
    }

    /**
     * @return list<string> each ':line: reason'
     */
    private function violationsIn(string $path, bool $forbidFileReads): array
    {
        $code = file_get_contents($path);
        self::assertNotFalse($code);

        $tokens = token_get_all($code);
        $found = [];
        $count = count($tokens);
        for ($i = 0; $i < $count; ++$i) {
            $token = $tokens[$i];
            if (!is_array($token)) {
                continue;
            }
            [$id, $text, $line] = $token;
            if ($id === T_NEW) {
                $next = $this->nextMeaningful($tokens, $i);
                if ($next === 'ParserFactory') {
                    $found[] = ':' . $line . ': new ParserFactory';
                }
                if ($next === 'AstPool') {
                    $found[] = ':' . $line . ': new AstPool';
                }
                continue;
            }
            if ($id === T_OBJECT_OPERATOR) {
                $next = $this->nextMeaningful($tokens, $i);
                if ($next === 'parse' && $this->followedByParen($tokens, $i, 'parse')) {
                    $found[] = ':' . $line . ': ->parse() call';
                }
                continue;
            }
            if (!$forbidFileReads) {
                continue;
            }
            if ($id === T_STRING && strtolower($text) === 'file_get_contents') {
                if ($this->isCallAt($tokens, $i)) {
                    $found[] = ':' . $line . ': file_get_contents() call';
                }
            }
        }

        return $found;
    }

    /**
     * Next meaningful token text after index $i (skips whitespace/comments).
     *
     * @param list<mixed> $tokens
     */
    private function nextMeaningful(array $tokens, int $i): ?string
    {
        $count = count($tokens);
        for ($j = $i + 1; $j < $count; ++$j) {
            $token = $tokens[$j];
            if (is_array($token)) {
                if (in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                return $token[1];
            }
            if (trim($token) === '') {
                continue;
            }

            return $token;
        }

        return null;
    }

    /**
     * @param list<mixed> $tokens
     */
    private function followedByParen(array $tokens, int $operatorIndex, string $name): bool
    {
        $count = count($tokens);
        for ($j = $operatorIndex + 1; $j < $count; ++$j) {
            $token = $tokens[$j];
            if (is_array($token)) {
                if (in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                if ($token[1] !== $name) {
                    return false;
                }
                // Found the method name; next meaningful must be '('.
                for ($k = $j + 1; $k < $count; ++$k) {
                    $after = $tokens[$k];
                    if (is_array($after)) {
                        if (in_array($after[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                            continue;
                        }

                        return false;
                    }

                    return $after === '(';
                }

                return false;
            }

            return false;
        }

        return false;
    }

    /**
     * @param list<mixed> $tokens
     */
    private function isCallAt(array $tokens, int $i): bool
    {
        // Skip function *declarations*: function file_get_contents( — previous
        // meaningful token would be T_FUNCTION.
        $prev = null;
        for ($j = $i - 1; $j >= 0; --$j) {
            $token = $tokens[$j];
            if (is_array($token)) {
                if (in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                $prev = $token[0];
                break;
            }
            if (trim($token) === '') {
                continue;
            }
            $prev = $token;
            break;
        }
        if ($prev === T_FUNCTION || $prev === T_OBJECT_OPERATOR || $prev === T_DOUBLE_COLON) {
            return false;
        }

        return $this->nextMeaningful($tokens, $i) === '(';
    }
}
