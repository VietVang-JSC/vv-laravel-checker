<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Frontend;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * JS syntax — unbalanced delimiters.
 *
 * Checks `resources/js`, `resources/ts`, `public/js` etc. for:
 * - unbalanced `{}`, `[]`, `()`
 * - unclosed string literals (`"`, `'`, `` ` ``)
 *
 * This is a heuristic, not a full parser — it ignores content inside
 * strings and comments. Severity Warning (dev should fix, not a security
 * gate). Confidence Medium — a template literal with `${}` is handled,
 * but dynamic code generation may still confuse it.
 */
final class JsSyntaxAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'JS_SYNTAX_ERROR';

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        $lower = strtolower(str_replace('\\', '/', $path));
        // Ignore minified and vendored assets — they are compiled, not authored
        if (str_contains($lower, '.min.') || str_contains($lower, '/vendor/') || str_contains($lower, '/node_modules/')) {
            return false;
        }
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if (in_array($ext, ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'], true)) {
            return true;
        }
        // Vue SFC script blocks are inside .vue files — check those too
        if ($ext === 'vue') {
            return true;
        }

        return false;
    }

    /**
     * @return list<Issue>
     */
    private function analyzeFile(string $file): array
    {
        $code = $this->sharedSource($file);
        if ($code === '') {
            return [];
        }

        // For .vue, only check <script> blocks
        if (str_ends_with(strtolower($file), '.vue')) {
            $code = $this->extractVueScript($code);
            if ($code === '') {
                return [];
            }
        }

        $result = $this->checkBalanced($code);
        if ($result === null) {
            return [];
        }

        return [
            new Issue(
                self::RULE,
                $result,
                $file,
                1,
                Severity::Warning,
                'custom',
                ['kind' => 'js_unbalanced'],
                Confidence::Medium
            ),
        ];
    }

    private function extractVueScript(string $code): string
    {
        if (preg_match_all('/<script[^>]*>(.*?)<\/script>/is', $code, $m) === 0) {
            return '';
        }

        return implode("\n", $m[1]);
    }

    /**
     * Returns error message or null if balanced.
     */
    private function checkBalanced(string $code): ?string
    {
        $stack = [];
        $pairs = ['}' => '{', ']' => '[', ')' => '('];
        $open = ['{' => true, '[' => true, '(' => true];

        $len = strlen($code);
        $inSingle = false;
        $inDouble = false;
        $inBacktick = false;
        $inLineComment = false;
        $inBlockComment = false;
        $escaped = false;

        for ($i = 0; $i < $len; $i++) {
            $c = $code[$i];
            $next = $i + 1 < $len ? $code[$i + 1] : '';

            if ($inLineComment) {
                if ($c === "\n") {
                    $inLineComment = false;
                }
                continue;
            }
            if ($inBlockComment) {
                if ($c === '*' && $next === '/') {
                    $inBlockComment = false;
                    $i++;
                }
                continue;
            }
            if ($inSingle) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($c === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($c === "'") {
                    $inSingle = false;
                }
                continue;
            }
            if ($inDouble) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($c === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($c === '"') {
                    $inDouble = false;
                }
                continue;
            }
            if ($inBacktick) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($c === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($c === '`') {
                    $inBacktick = false;
                    continue;
                }
                // Handle ${} inside template literal — count braces inside
                if ($c === '$' && $next === '{') {
                    $stack[] = '{';
                    $i++;
                    continue;
                }
                continue;
            }

            // Not in string/comment
            if ($c === '/' && $next === '/') {
                $inLineComment = true;
                $i++;
                continue;
            }
            if ($c === '/' && $next === '*') {
                $inBlockComment = true;
                $i++;
                continue;
            }
            if ($c === "'") {
                $inSingle = true;
                continue;
            }
            if ($c === '"') {
                $inDouble = true;
                continue;
            }
            if ($c === '`') {
                $inBacktick = true;
                continue;
            }

            if (isset($open[$c])) {
                $stack[] = $c;
            } elseif (isset($pairs[$c])) {
                if ($stack === []) {
                    return sprintf('Unmatched closing `%s` at offset %d.', $c, $i);
                }
                $last = array_pop($stack);
                if ($last !== $pairs[$c]) {
                    return sprintf('Mismatched delimiters: expected `%s` to close `%s` but found `%s`.', $pairs[$c], $last, $c);
                }
            }
        }

        if ($inSingle) {
            return 'Unclosed single-quoted string.';
        }
        if ($inDouble) {
            return 'Unclosed double-quoted string.';
        }
        if ($inBacktick) {
            return 'Unclosed template literal (backtick).';
        }
        if ($inBlockComment) {
            return 'Unclosed block comment /*.';
        }
        if ($stack !== []) {
            $unclosed = end($stack);
            return sprintf('Unclosed `%s` — missing closing `%s`.', $unclosed, array_search($unclosed, $pairs, true) ?: '?');
        }

        return null;
    }
}
