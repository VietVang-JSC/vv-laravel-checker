<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
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
 * `json_encode(...)` with all four JSON_HEX_* flags, framework event-hook
 * output (`view_render_event(...)`), the escaped `{{ ... }}` syntax (which is
 * safe by definition), paginator `->links(...)` / `->appends(...)->render()`
 * output, and variables whose
 * name marks pre-rendered/sanitized HTML (`$commentHtml`, `$page->getHtml()`).
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
     * json_encode() flags that neutralize script breakouts.
     */
    private const JSON_HEX_FLAGS = ['JSON_HEX_TAG', 'JSON_HEX_APOS', 'JSON_HEX_AMP', 'JSON_HEX_QUOT'];

    /**
     * Framework event hooks and form builders whose output comes from internal
     * rendering (values escaped by the builder), not raw user data — e.g.
     * `{!! view_render_event('...') !!}` theming hooks,
     * Laravel Collective `{!! Form::open(...) !!}` / `{!! Html::link(...) !!}`,
     * and paginator `{!! $rows->links() !!}` / `{!! $rows->appends([...])->render() !!}`.
     */
    private const EVENT_FUNCS = ['view_render_event', 'form::', 'html::', 'number::'];

    /**
     * Verified numeric formatter functions whose output is HTML-safe by
     * construction (NumberFormatter float-cast): the amount is numeric and
     * the symbol is admin-configured data. Laravel's Number:: helper is
     * covered by the number:: prefix in EVENT_FUNCS above.
     */
    private const FORMATTER_FUNCS = ['format_amount_by_'];

    /**
     * View-name directives whose argument selects a template file. The
     * extends/include/includeIf/each family takes the view as the first
     * argument; includeWhen takes it as the second (after the condition).
     */
    private const VIEW_DIRECTIVES = ['extends', 'include', 'includeif', 'includewhen', 'includefirst', 'each'];

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

        return array_merge($this->analyzeEchoes($file, $content), $this->analyzeViewDirectives($file, $content));
    }

    /**
     * @return Issue[]
     */
    private function analyzeEchoes(string $file, string $content): array
    {
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

            if ($this->isHexEncodedJson($inner)) {
                continue;
            }

            if ($this->isEventOutput($inner)) {
                continue;
            }

            if (str_contains($inner, '->links(')) {
                continue;
            }

            if (str_contains($inner, '->appends(') && str_contains($inner, '->render()')) {
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

    /**
     * Dynamic view names (@include($view), @extends('dir.' . $theme), ...):
     * the resolved template executes embedded PHP, so a user-steerable name
     * is a local file inclusion vector. String literals (including arrays of
     * literals for @includeFirst) stay silent — Blade has no data-flow
     * analysis, so anything else is Medium confidence.
     *
     * @return Issue[]
     */
    private function analyzeViewDirectives(string $file, string $content): array
    {
        $matches = [];
        $alternation = implode('|', self::VIEW_DIRECTIVES);
        if (preg_match_all('/@(' . $alternation . ')\s*(\((?:[^()]|(?2))*\))/i', $content, $matches, PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        $issues = [];
        foreach ($matches[1] as $index => $directive) {
            $name = strtolower((string) $directive[0]);
            $paren = (string) $matches[2][$index][0];
            $offset = (int) $matches[0][$index][1];
            $view = $this->viewArgument($name, $paren);
            if ($view === null || !$this->isDynamicView($view)) {
                continue;
            }

            $line = substr_count(substr($content, 0, $offset), "\n") + 1;
            $sink = '@' . $name . $paren;
            if (strlen($sink) > 120) {
                $sink = substr($sink, 0, 117) . '...';
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                'Potential Blade LFI: dynamic view name in @' . $name . ' can load an unintended template — pin it to a string literal or an allow-list.',
                $file,
                $line,
                Severity::Error,
                ['sink' => $sink, 'kind' => 'dynamic-include'],
                Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * The template-selecting argument: second for @includeWhen (the first is
     * the condition), first otherwise.
     */
    private function viewArgument(string $directive, string $paren): ?string
    {
        $inner = trim($paren);
        if (!str_starts_with($inner, '(') || !str_ends_with($inner, ')')) {
            return null;
        }
        $args = $this->splitTopLevel(substr($inner, 1, -1));
        if ($directive === 'includewhen') {
            return isset($args[1]) ? trim($args[1]) : null;
        }

        return isset($args[0]) && trim($args[0]) !== '' ? trim($args[0]) : null;
    }

    /**
     * @return list<string>
     */
    private function splitTopLevel(string $args): array
    {
        $parts = [];
        $depth = 0;
        $quote = null;
        $current = '';
        $length = strlen($args);
        for ($i = 0; $i < $length; $i++) {
            $char = $args[$i];
            if ($quote !== null) {
                $current .= $char;
                if ($char === $quote && ($i === 0 || $args[$i - 1] !== '\\')) {
                    $quote = null;
                }
                continue;
            }
            if ($char === "'" || $char === '"') {
                $quote = $char;
                $current .= $char;
                continue;
            }
            if ($char === '(' || $char === '[' || $char === '{') {
                $depth++;
            } elseif ($char === ')' || $char === ']' || $char === '}') {
                $depth = max(0, $depth - 1);
            }
            if ($char === ',' && $depth === 0) {
                $parts[] = $current;
                $current = '';
                continue;
            }
            $current .= $char;
        }
        $parts[] = $current;

        return $parts;
    }

    private function isDynamicView(string $view): bool
    {
        $trimmed = trim($view);
        if ($trimmed === '') {
            return false;
        }
        // Any $ variable makes the name steerable — including a concat like
        // 'layouts.' . $theme that merely starts with a literal.
        if (str_contains($view, '$')) {
            return true;
        }
        // A bare call (viewName(), ...) cannot be resolved statically, except
        // deploy-time config()/env() lookups which are safe by convention.
        if (str_contains($view, '(')) {
            return preg_match('/^\s*(config|env)\s*\(/i', $trimmed) !== 1;
        }

        return false;
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
            $needle = str_ends_with($fn, '::') ? $fn : $fn . '(';
            if (str_contains($lower, $needle)) {
                return true;
            }
        }
        foreach (self::FORMATTER_FUNCS as $fn) {
            // Prefix entries (ending in _) match the family:
            // format_amount_by_ covers _symbol/_code/_currency/_account.
            $needle = str_ends_with($fn, '_') ? $fn : $fn . '(';
            if (str_contains($lower, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * json_encode() with all four HEX flags neutralizes `</script>` breakouts;
     * without them the output stays flaggable.
     */
    private function isHexEncodedJson(string $inner): bool
    {
        if (!str_contains($inner, 'json_encode(')) {
            return false;
        }

        foreach (self::JSON_HEX_FLAGS as $flag) {
            if (!str_contains($inner, $flag)) {
                return false;
            }
        }

        return true;
    }
}
