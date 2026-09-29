<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Profiling;

/**
 * Lightweight scan profiler (PERF-EVAL-1, extended PERF-EVAL-2). OFF by
 * default — every probe is a single boolean check, so disabled overhead
 * is noise. Enable via `CheckContext::$profile` or the
 * `QUALITY_CHECKER_PROFILE` env var.
 *
 * Measures, never influences: findings are byte-identical with the
 * profiler on or off. Output is a plain array for machine-readable
 * reports (see the --profile driver output).
 *
 * PERF-EVAL-2 additions: traversal/node counting (attributed to the
 * analyzer active in timeAnalyzer, inclusive of its semantic-index
 * work), canonical-node census, per-analyzer issue counts, and an
 * add() accumulator for phases timed outside begin/end.
 */
final class Profiler
{
    private static bool $enabled = false;

    /** @var array<string, float> */
    private static array $timers = [];

    /** @var array<string, float> */
    private static array $started = [];

    /** @var array<string, int> */
    private static array $counters = [];

    /** @var array<string, true> */
    private static array $uniqueReads = [];

    /** @var array<string, true> */
    private static array $uniqueParses = [];

    private static ?string $context = null;

    public static function setEnabled(bool $enabled): void
    {
        self::$enabled = $enabled;
    }

    public static function enableFromEnvironment(): void
    {
        $flag = getenv('QUALITY_CHECKER_PROFILE');
        if (is_string($flag) && $flag !== '' && $flag !== '0') {
            self::$enabled = true;
        }
    }

    public static function isEnabled(): bool
    {
        return self::$enabled;
    }

    public static function reset(): void
    {
        self::$timers = [];
        self::$started = [];
        self::$counters = [];
        self::$uniqueReads = [];
        self::$uniqueParses = [];
        self::$context = null;
    }

    /**
     * Accumulate an externally-measured span (phases timed with a local
     * microtime pair instead of begin/end).
     */
    public static function add(string $section, float $seconds): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$timers[$section] = (self::$timers[$section] ?? 0.0) + $seconds;
    }

    public static function begin(string $section): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$started[$section] = microtime(true);
    }

    public static function end(string $section): void
    {
        if (!self::$enabled) {
            return;
        }
        if (!isset(self::$started[$section])) {
            return;
        }
        $elapsed = microtime(true) - self::$started[$section];
        unset(self::$started[$section]);
        self::$timers[$section] = (self::$timers[$section] ?? 0.0) + $elapsed;
    }

    /**
     * Time one analyzer end-to-end (wall time, includes its own parsing).
     * Sets the attribution context so traversal probes inside (analyzer
     * body + its semantic-index builds) credit this analyzer.
     *
     * @return mixed analyzer result
     */
    public static function timeAnalyzer(string $name, callable $run): mixed
    {
        if (!self::$enabled) {
            return $run();
        }
        $start = microtime(true);
        $previous = self::$context;
        self::$context = $name;
        try {
            return $run();
        } finally {
            $key = 'analyzer:' . $name;
            self::$timers[$key] = (self::$timers[$key] ?? 0.0) + (microtime(true) - $start);
            self::$context = $previous;
        }
    }

    /**
     * One full-tree walk finished (a NodeFinder find/findFirst call,
     * including instanceof variants which delegate). $nodes = exact
     * nodes the filter was tested against.
     */
    public static function countTraversal(int $nodes): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['traversals'] = (self::$counters['traversals'] ?? 0) + 1;
        self::$counters['traversal_nodes'] = (self::$counters['traversal_nodes'] ?? 0) + $nodes;
        $scope = self::$context ?? 'none';
        self::$counters['trav:' . $scope] = (self::$counters['trav:' . $scope] ?? 0) + 1;
        self::$counters['travnodes:' . $scope] = (self::$counters['travnodes:' . $scope] ?? 0) + $nodes;
    }

    /**
     * Canonical-tree census: nodes linked into the shared ASTs
     * (counted once per file inside the single linker traversal —
     * no extra walk).
     */
    public static function countCanonicalNodes(int $nodes): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['canonical_nodes'] = (self::$counters['canonical_nodes'] ?? 0) + $nodes;
    }

    public static function countIssues(string $analyzer, int $count): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['issues:' . $analyzer] = (self::$counters['issues:' . $analyzer] ?? 0) + $count;
    }

    public static function countRead(string $path): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['file_reads'] = (self::$counters['file_reads'] ?? 0) + 1;
        self::$uniqueReads[$path] = true;
    }

    public static function countParse(?string $path = null): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['parse_operations'] = (self::$counters['parse_operations'] ?? 0) + 1;
        if ($path !== null) {
            self::$uniqueParses[$path] = true;
        }
    }

    public static function countFilesVisited(string $analyzer, int $count): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['file_visits'] = (self::$counters['file_visits'] ?? 0) + $count;
        $key = 'visits:' . $analyzer;
        self::$counters[$key] = (self::$counters[$key] ?? 0) + $count;
    }

    public static function gauge(string $key, int|float $value): void
    {
        if (!self::$enabled) {
            return;
        }
        self::$counters['gauge:' . $key] = (int) $value;
    }

    /**
     * @return array{timers_ms: array<string, float>, counters: array<string, int>, unique_files_read: int, unique_files_parsed: int, peak_mb: float}
     */
    public static function report(): array
    {
        $timers = [];
        foreach (self::$timers as $section => $seconds) {
            $timers[$section] = round($seconds * 1000, 1);
        }

        return [
            'timers_ms' => $timers,
            'counters' => self::$counters,
            'unique_files_read' => count(self::$uniqueReads),
            'unique_files_parsed' => count(self::$uniqueParses),
            'peak_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 1),
        ];
    }
}
