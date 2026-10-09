<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Frontend;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * CSS syntax — unbalanced braces and missing semicolons.
 *
 * Checks `resources/css`, `resources/scss`, `public/css` etc. for:
 * - unbalanced `{}`
 * - missing `;` before `}` inside a rule block
 *
 * Heuristic only — not a full CSS parser. Warning/Medium.
 */
final class CssSyntaxAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'CSS_SYNTAX_ERROR';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
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
        if (str_contains($lower, '.min.') || str_contains($lower, '/vendor/') || str_contains($lower, '/node_modules/')) {
            return false;
        }
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        return in_array($ext, ['css', 'scss', 'sass', 'less'], true);
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

        $issues = [];
        $braceError = $this->checkBraces($code);
        if ($braceError !== null) {
            $issues[] = new Issue(
                self::RULE,
                $braceError,
                $file,
                1,
                Severity::Warning,
                'custom',
                ['kind' => 'css_brace'],
                Confidence::Medium
            );
        }

        $semiError = $this->checkMissingSemicolon($code);
        if ($semiError !== null) {
            $issues[] = new Issue(
                self::RULE,
                $semiError,
                $file,
                1,
                Severity::Info,
                'custom',
                ['kind' => 'css_semicolon'],
                Confidence::Low
            );
        }

        return $issues;
    }

    private function checkBraces(string $code): ?string
    {
        // Strip comments
        $code = preg_replace('!/\*.*?\*/!s', '', $code) ?? $code;
        $code = preg_replace('/\/\/.*$/m', '', $code) ?? $code;

        $depth = 0;
        $len = strlen($code);
        $inString = false;
        $stringChar = '';
        $escaped = false;

        for ($i = 0; $i < $len; $i++) {
            $c = $code[$i];
            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($c === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($c === $stringChar) {
                    $inString = false;
                }
                continue;
            }
            if ($c === '"' || $c === "'") {
                $inString = true;
                $stringChar = $c;
                continue;
            }
            if ($c === '{') {
                $depth++;
            } elseif ($c === '}') {
                $depth--;
                if ($depth < 0) {
                    return sprintf('Unmatched closing `}` at offset %d.', $i);
                }
            }
        }

        if ($depth > 0) {
            return sprintf('Unclosed `{` — missing %d closing `}`.', $depth);
        }

        return null;
    }

    private function checkMissingSemicolon(string $code): ?string
    {
        // Very small heuristic: inside a block, a line like "color: red }" without ;
        // Strip comments and strings for simplicity — check for pattern ":\s*[^;{}]+\s*}"
        $code = preg_replace('!/\*.*?\*/!s', '', $code) ?? $code;
        if (preg_match('/:[^;{}]*\s*}/', $code, $m) === 1) {
            // Ensure it's not a nested rule like "&:hover {"
            $sample = trim($m[0]);
            if (str_contains($sample, ':') && !str_contains($sample, '{')) {
                return 'Possible missing `;` before `}` (e.g. `color: red }`).';
            }
        }

        return null;
    }
}
