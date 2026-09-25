<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03 Blade unescaped echo XSS.
 *
 * Assumes: any {!! ... !!} block containing dynamic data (a `$` variable or a
 * `request(` call) in a *.blade.php file is an unescaped-output sink and is reported.
 * Raw file content is scanned with regex because Blade templates are not valid PHP
 * and must not be parsed with PHP-Parser.
 *
 * Deliberately not flagged: {!! ... !!} blocks without dynamic data (e.g.
 * `{!! csrf_field() !!}`), blocks already escaped/sanitized via `e(...)`,
 * `sanitizeHtml(...)`, `strip_tags(...)`, `htmlspecialchars(...)` and alike,
 * framework event-hook output (`view_render_event(...)`), the escaped
 * `{{ ... }}` syntax (which is safe by definition), paginator
 * `->links(...)` output, and variables whose name marks pre-rendered/
 * sanitized HTML (`$commentHtml`, `$page->getHtml()`).
 */
final class OwaspBladeXssAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_BLADE_XSS';

    /**
     * Explicit sanitizer/escaper calls wrapping the output.
     */
    private const SANITIZER_FUNCS = [
        'e', 'sanitizehtml', 'strip_tags', 'htmlspecialchars', 'htmlentities', 'purify', 'clean',
    ];

    /**
     * Framework event hooks whose output comes from internal listeners, not
     * user data (e.g. Bagisto `{!! view_render_event('...') !!}` theming hook
     * present in hundreds of templates).
     */
    private const EVENT_FUNCS = ['view_render_event'];

    public function supports(string $path): bool
    {
        return str_ends_with(strtolower($path), '.blade.php');
    }

    /**
     * @param list<string> $files absolute paths
     * @return Issue[]
     */
    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isTestPath($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @return Issue[]
     */
    private function analyzeFile(string $file): array
    {
        $content = $this->readFile($file);
        if ($content === '') {
            return [];
        }

        $matches = [];
        if (preg_match_all('/\{!!(.*?)!!\}/s', $content, $matches, PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        /** @var list<array{string, int}> $blocks */
        $blocks = $matches[1];
        /** @var list<array{string, int}> $fullMatches */
        $fullMatches = $matches[0];

        $issues = [];
        foreach ($blocks as $index => $block) {
            [$inner, $offset] = $block;
            $full = (string) ($fullMatches[$index][0] ?? '');

            if ($this->isSanitized($inner)) {
                continue;
            }

            if ($this->isEventOutput($inner)) {
                continue;
            }

            if (str_contains($inner, '->links(')) {
                continue;
            }

            if (preg_match('/\$\w*(html|rendered|sanitized|purified|markup)/i', $inner) === 1) {
                continue;
            }

            if (preg_match('/->\w*(html|rendered|sanitized|purified|markup)/i', $inner) === 1) {
                continue;
            }

            if (!str_contains($inner, '$') && !str_contains($inner, 'request(')) {
                continue;
            }

            $line = substr_count(substr($content, 0, (int) $offset), "\n") + 1;
            $sink = trim($full);
            if (strlen($sink) > 120) {
                $sink = substr($sink, 0, 117) . '...';
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                'Potential Blade XSS: unescaped output {!! ... !!} contains dynamic data.',
                $file,
                $line,
                Severity::Error,
                ['sink' => $sink]
            );
        }

        return $issues;
    }

    private function isSanitized(string $inner): bool
    {
        $lower = strtolower($inner);
        foreach (self::SANITIZER_FUNCS as $fn) {
            if (preg_match('/\b' . preg_quote($fn, '/') . '\s*\(/', $lower) === 1) {
                return true;
            }
        }

        return false;
    }

    private function isEventOutput(string $inner): bool
    {
        $lower = strtolower($inner);
        foreach (self::EVENT_FUNCS as $fn) {
            if (str_contains($lower, $fn . '(')) {
                return true;
            }
        }

        return false;
    }
}
