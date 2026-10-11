<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class EolAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'EOL_COMPONENT';

    /**
     * Security-support end dates (EOL) per major line.
     *
     * Sources: laravel.com/docs/releases (bug/security fix windows) and
     * php.net/supported-versions.php (security-support end = EOL).
     * Refresh when a new major ships; unknown majors never fire.
     *
     * @var array<int, string>
     */
    private const LARAVEL_EOL = [
        9 => '2024-02-06',
        10 => '2025-02-04',
        11 => '2026-03-12',
        12 => '2027-02-24',
        13 => '2028-03-17',
    ];

    /**
     * @var array<string, string> minor line => EOL date
     */
    private const PHP_EOL = [
        '8.0' => '2023-11-26',
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $composer = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composer)) {
            return [];
        }
        $code = $this->sharedSource($composer);
        if ($code === '') {
            return [];
        }
        $data = json_decode($code, true);
        if (!is_array($data)) {
            return [];
        }
        $requires = $data['require'] ?? [];
        if (!is_array($requires)) {
            return [];
        }
        $issues = [];
        $laravel = $requires['laravel/framework'] ?? null;
        if (is_string($laravel)) {
            foreach ($this->eolLaravelMajors($laravel) as $major => $eol) {
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('laravel/framework %s is end-of-life since %s — upgrade.', $laravel, $eol),
                    $composer,
                    1,
                    Severity::Warning,
                    'custom',
                    ['package' => 'laravel/framework', 'constraint' => $laravel, 'major' => $major, 'eol' => $eol],
                    Confidence::Medium
                );
            }
        }
        $php = $requires['php'] ?? null;
        if (is_string($php)) {
            foreach ($this->eolPhpLines($php) as $line => $eol) {
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('php %s is end-of-life since %s — upgrade.', $php, $eol),
                    $composer,
                    1,
                    Severity::Warning,
                    'custom',
                    ['package' => 'php', 'constraint' => $php, 'line' => $line, 'eol' => $eol],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    /**
     * Laravel majors pinned by the constraint whose security support ended.
     *
     * A constraint allowing ANY supported major (e.g. `^11.0|^12.0`) does not
     * fire: the project can resolve to a live line. Only fire when every
     * major mentioned is EOL (single-major pins like `^11.0` are the norm).
     * Constraints with no parseable major never fire (unknown, not EOL).
     *
     * @return array<int, string> major => eol date
     */
    private function eolLaravelMajors(string $constraint): array
    {
        preg_match_all('/\b(\d{1,2})(?:\.\d+){0,2}\b/', $constraint, $m);
        $majors = [];
        foreach ($m[1] as $raw) {
            $major = (int) $raw;
            if ($major >= 6 && $major <= 20) {
                $majors[$major] = true;
            }
        }
        if ($majors === []) {
            return [];
        }
        $now = time();
        $eol = [];
        foreach (array_keys($majors) as $major) {
            $date = self::LARAVEL_EOL[$major] ?? null;
            if ($date === null) {
                // Unknown major (future release): treat as supported.
                return [];
            }
            if (strtotime($date) >= $now) {
                // At least one supported line allowed: not EOL.
                return [];
            }
            $eol[$major] = $date;
        }

        return $eol;
    }

    /**
     * PHP minor lines pinned by the constraint whose support ended.
     *
     * Same any-supported-wins rule as Laravel. `>=8.1` style open ranges
     * mention a floor but allow newer lines, so they never fire — only
     * exact pins (`8.1.*`, `~8.1.0`, `^8.1`) and closed sets of EOL lines do.
     *
     * @return array<string, string> line => eol date
     */
    private function eolPhpLines(string $constraint): array
    {
        if (preg_match('/>=/', $constraint)) {
            return [];
        }
        preg_match_all('/\b(8\.\d|7\.\d)\b/', $constraint, $m);
        $lines = array_unique($m[1]);
        if ($lines === []) {
            return [];
        }
        $now = time();
        $eol = [];
        foreach ($lines as $line) {
            $date = self::PHP_EOL[$line] ?? null;
            if ($date === null) {
                return [];
            }
            if (strtotime($date) >= $now) {
                return [];
            }
            $eol[$line] = $date;
        }

        return $eol;
    }
}
