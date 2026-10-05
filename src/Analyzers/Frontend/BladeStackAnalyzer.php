<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Frontend;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Blade @stack / @push / @prepend declaration check.
 *
 * In Laravel Blade:
 * - `@stack('scripts')` in a layout declares a placeholder
 * - `@push('scripts') ... @endpush` or `@prepend('scripts') ... @endprepend` fills it
 *
 * This analyzer is a declaration checker, not a runtime verifier. It reports:
 * - `@push('x')` without a matching `@stack('x')` anywhere in `resources/views` (orphan push)
 * - `@stack('x')` without any `@push('x')`/`@prepend('x')` (empty stack — info only, often intentional)
 * - `@push('x')` without a closing `@endpush` (or `@prepend` without `@endprepend`) — unclosed block
 * - Mismatched names: `@push('scripts')` vs `@stack('script')` (typo) — caught as orphan
 *
 * Severity: orphan push → Warning (likely typo, script never renders)
 *           unclosed block → Error (Blade will throw)
 *           empty stack → Info (often intentional, e.g. optional stacks)
 * Confidence Medium — cross-file, so a stack in a vendor view or a push in a
 * dynamically included view may be missed. Use `quality-checker-ignore` if intentional.
 */
final class BladeStackAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'BLADE_STACK_MISMATCH';

    public function analyze(array $files): array
    {
        // Only inspect once per run — collect all blade files
        $bladeFiles = array_values(array_filter($files, fn (string $f): bool => str_ends_with(strtolower($f), '.blade.php')));
        if ($bladeFiles === []) {
            return [];
        }

        $stacks = []; // name => list of files
        $pushes = []; // name => list of files
        $unclosed = []; // file => message

        foreach ($bladeFiles as $file) {
            $code = $this->sharedSource($file);
            if ($code === '') {
                continue;
            }

            // Find @stack('name') — allow " or ' and spacing
            if (preg_match_all('/@stack\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)/', $code, $m) > 0) {
                foreach ($m[1] as $name) {
                    $stacks[$name][] = $file;
                }
            }

            // Find @push('name') and @prepend('name')
            if (preg_match_all('/@push\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)/', $code, $m) > 0) {
                foreach ($m[1] as $name) {
                    $pushes[$name][] = $file;
                }
            }
            if (preg_match_all('/@prepend\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)/', $code, $m) > 0) {
                foreach ($m[1] as $name) {
                    $pushes[$name][] = $file;
                }
            }

            // Check for unclosed @push/@prepend
            $pushCount = preg_match_all('/@push\s*\(/', $code);
            $prependCount = preg_match_all('/@prepend\s*\(/', $code);
            $endPushCount = substr_count($code, '@endpush');
            $endPrependCount = substr_count($code, '@endprepend');

            if ($pushCount > $endPushCount) {
                $unclosed[$file] = sprintf('@push without @endpush (%d push vs %d endpush)', $pushCount, $endPushCount);
            }
            if ($prependCount > $endPrependCount) {
                $msg = sprintf('@prepend without @endprepend (%d prepend vs %d endprepend)', $prependCount, $endPrependCount);
                $unclosed[$file] = isset($unclosed[$file]) ? $unclosed[$file] . '; ' . $msg : $msg;
            }
        }

        $issues = [];

        foreach ($unclosed as $file => $msg) {
            $issues[] = new Issue(
                self::RULE,
                'Blade stack block unclosed: ' . $msg . '.',
                $file,
                1,
                Severity::Error,
                'custom',
                ['kind' => 'unclosed_block'],
                Confidence::High
            );
        }

        foreach ($pushes as $name => $files) {
            if (!isset($stacks[$name])) {
                $sample = $files[0];
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('@push(\'%s\') has no matching @stack(\'%s\') — content will never render (typo?).', $name, $name),
                    $sample,
                    1,
                    Severity::Warning,
                    'custom',
                    ['kind' => 'orphan_push', 'stack' => $name, 'files' => $files],
                    Confidence::Medium
                );
            }
        }

        foreach ($stacks as $name => $files) {
            if (!isset($pushes[$name])) {
                $sample = $files[0];
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('@stack(\'%s\') has no matching @push — stack will always be empty.', $name),
                    $sample,
                    1,
                    Severity::Info,
                    'custom',
                    ['kind' => 'empty_stack', 'stack' => $name],
                    Confidence::Low
                );
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return str_ends_with(strtolower($path), '.blade.php');
    }
}
