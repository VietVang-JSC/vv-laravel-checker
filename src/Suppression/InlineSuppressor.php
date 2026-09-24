<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Suppression;

use VietVang\QualityChecker\Result\Issue;

/**
 * Inline per-finding suppression via source comments.
 *
 * Supported forms (line `//`, `#` or single-line block comments):
 *
 *   $x = $_GET['v']; // quality-checker-ignore TAINT_XSS,TAINT_SQL_INJECTION
 *   // quality-checker-ignore-next-line OWASP_SSRF
 *   $data = file_get_contents($url);
 *
 * A bare `all` (or `*`) in place of the rule list suppresses every rule for
 * that line. Matching is exact against `Issue::$rule`. Suppressed issues are
 * dropped from the result set; use the returned count for reporting.
 */
final class InlineSuppressor
{
    /** @var array<string, list<string>> absolute path => source lines (1-indexed logically) */
    private array $lineCache = [];

    private int $suppressedCount = 0;

    /**
     * @param Issue[] $issues
     * @return Issue[] issues without the suppressed ones
     */
    public function filter(array $issues): array
    {
        $this->suppressedCount = 0;
        $kept = [];
        foreach ($issues as $issue) {
            if ($this->isSuppressed($issue)) {
                $this->suppressedCount++;
                continue;
            }
            $kept[] = $issue;
        }

        return $kept;
    }

    public function countSuppressed(): int
    {
        return $this->suppressedCount;
    }

    private function isSuppressed(Issue $issue): bool
    {
        $file = $issue->file;
        $line = $issue->line;
        if (!is_string($file) || $file === '' || !is_int($line) || $line < 1 || !is_file($file)) {
            return false;
        }

        $lines = $this->linesOf($file);
        $current = $lines[$line - 1] ?? null;
        if (is_string($current) && $this->matches($current, $issue->rule, false)) {
            return true;
        }

        $previous = $line >= 2 ? ($lines[$line - 2] ?? null) : null;
        if (is_string($previous) && $this->matches($previous, $issue->rule, true)) {
            return true;
        }

        return false;
    }

    private function matches(string $line, string $rule, bool $nextLineForm): bool
    {
        $marker = $nextLineForm ? 'quality-checker-ignore-next-line' : 'quality-checker-ignore';
        $pattern = '/(?:\/\/|#|\/\*).*?' . preg_quote($marker, '/') . '\s+([A-Za-z0-9_,\s*]+)/';

        if (preg_match($pattern, $line, $m) !== 1) {
            return false;
        }

        $tokens = preg_split('/[\s,]+/', trim($m[1]));
        if (!is_array($tokens)) {
            return false;
        }

        foreach ($tokens as $token) {
            if ($token === '') {
                continue;
            }
            if (strtolower($token) === 'all' || $token === '*') {
                return true;
            }
            if ($token === $rule) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function linesOf(string $file): array
    {
        if (!isset($this->lineCache[$file])) {
            $content = (string) file_get_contents($file);
            $this->lineCache[$file] = explode("\n", str_replace(["\r\n", "\r"], "\n", $content));
        }

        return $this->lineCache[$file];
    }
}
