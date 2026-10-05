<?php

/**
 * Re-runnable finding-count benchmark over projects you choose.
 *
 * The README's benchmark table is a snapshot: it records how many findings this
 * tool produced on 27 real applications on one day, measured by hand. Nothing
 * re-measured it, so an analyzer change can move the numbers without anyone
 * noticing, and no one outside this repository can check the numbers at all.
 *
 * This script closes both halves of that. It takes *your* project list, scans
 * each one with a fixed set of flags, and prints a per-rule table. Point it at
 * your own codebase to see what this tool reports on your code, and keep the
 * output as a baseline: run it again after upgrading and the diff shows whether
 * a new release finds more, less, or the same.
 *
 * Your project list is a local file you keep. Nothing here contacts a network
 * service, and no project list ships with the package.
 *
 * Usage:
 *   php tools/benchmark-projects.php <manifest.json> [--baseline=out.json] [--update]
 *   php tools/benchmark-projects.php <manifest.json> --diff=baseline.json
 *
 * Manifest format — paths are local, and each entry may pin a `--tier` or its
 * own flag overrides:
 *
 *   {
 *     "defaults": { "tier": "security", "min_confidence": "low" },
 *     "targets": [
 *       { "name": "my-app",    "path": "C:/src/my-app" },
 *       { "name": "my-package", "path": "C:/src/my-lib", "min_confidence": "medium" },
 *       { "name": "skip-me",   "path": "C:/src/old", "enabled": false }
 *     ]
 *   }
 *
 * Every target is scanned the way the README table is: custom analyzers only,
 * `--fail-on=none` so findings never fail the run, and no cache, because a warm
 * cache would report the previous run's numbers.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use Rampart\QualityChecker\Result\PackageVersion;

$root = dirname(__DIR__);

// ------------------------------------------------------------------ arguments ---

$manifestPath = null;
$baselinePath = null;
$diffPath = null;
$update = false;

foreach (array_slice($argv, 1) as $argument) {
    if ($argument === '--update') {
        $update = true;
        continue;
    }
    if (str_starts_with($argument, '--baseline=')) {
        $baselinePath = substr($argument, 11);
        continue;
    }
    if (str_starts_with($argument, '--diff=')) {
        $diffPath = substr($argument, 7);
        continue;
    }
    if (!str_starts_with($argument, '--') && $manifestPath === null) {
        $manifestPath = $argument;
        continue;
    }
    fwrite(STDERR, 'Unknown argument: ' . $argument . PHP_EOL);
    exit(2);
}

if ($manifestPath === null) {
    fwrite(STDERR, <<<TXT
    Usage: php tools/benchmark-projects.php <manifest.json> [options]

      --baseline=FILE   write the measured counts to FILE
      --diff=FILE       compare against FILE and fail on drift
      --update          overwrite FILE passed to --baseline if it exists

    The manifest is yours and stays local. See the header of this file for its
    format.

    TXT);
    exit(2);
}

if (!is_file($manifestPath)) {
    fwrite(STDERR, 'Manifest not found: ' . $manifestPath . PHP_EOL);
    exit(2);
}

// -------------------------------------------------------------------- helpers ---

$failures = [];

$fail = static function (string $message) use (&$failures): void {
    $failures[] = $message;
    echo '  FAIL  ' . $message . PHP_EOL;
};

$note = static function (string $message): void {
    echo '  ' . $message . PHP_EOL;
};

/**
 * Run the packaged binary against one project and return its findings.
 *
 * The command is an array, not a shell string, for the same reason the smoke
 * test uses one where it can: Symfony and proc_open both bypass the shell for
 * an argument array, so a project path containing a space or a quote cannot
 * turn into a different command. Windows gets the shell string only because
 * the .bat shim cannot be executed otherwise.
 *
 * @param list<string> $command
 * @return array{code: int, stdout: string, stderr: string}
 */
$run = static function (array $command, string $cwd, int $timeout): array {
    $stdoutPath = tempnam(sys_get_temp_dir(), 'qc-bench-out');
    $stderrPath = tempnam(sys_get_temp_dir(), 'qc-bench-err');
    $stdinPath = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $isWindows = PHP_OS_FAMILY === 'Windows';

    $process = proc_open(
        $isWindows ? implode(' ', $command) : $command,
        [0 => ['file', $stdinPath, 'r'], 1 => ['file', $stdoutPath, 'w'], 2 => ['file', $stderrPath, 'w']],
        $pipes,
        $cwd
    );

    if (!is_resource($process)) {
        return ['code' => 1, 'stdout' => '', 'stderr' => 'could not start ' . implode(' ', $command)];
    }

    $deadline = microtime(true) + $timeout;
    $timedOut = false;
    $code = -1;

    while (true) {
        $status = proc_get_status($process);
        if ($status['running'] === false) {
            $code = (int) $status['exitcode'];
            break;
        }
        if (microtime(true) >= $deadline) {
            $timedOut = true;
            $pid = (int) $status['pid'];
            // Kill the tree. On Windows the child is cmd.exe -> php.exe, and
            // terminating cmd.exe alone orphans the php process, which keeps
            // scanning after this script has given up on it.
            if ($isWindows && $pid > 0) {
                @exec('taskkill /F /T /PID ' . $pid . ' 2>&1');
            }
            proc_terminate($process, 9);
            $code = 124;
            break;
        }
        usleep(100000);
    }

    proc_close($process);

    $stdout = (string) @file_get_contents($stdoutPath);
    $stderr = (string) @file_get_contents($stderrPath);
    @unlink($stdoutPath);
    @unlink($stderrPath);

    if ($timedOut) {
        $stderr .= PHP_EOL . 'killed after ' . $timeout . 's without finishing';
    }

    return ['code' => $code, 'stdout' => $stdout, 'stderr' => $stderr];
};

/**
 * @return array{total: int, by_rule: array<string, int>, by_severity: array<string, int>}
 */
$summarize = static function (string $reportPath): array {
    $payload = json_decode((string) @file_get_contents($reportPath), true);
    if (!is_array($payload)) {
        return ['total' => 0, 'by_rule' => [], 'by_severity' => []];
    }

    $byRule = [];
    $bySeverity = ['critical' => 0, 'error' => 0, 'warning' => 0, 'info' => 0];
    $total = 0;

    foreach ($payload['checkers'] ?? [] as $checker) {
        foreach ($checker['issues'] ?? [] as $issue) {
            $rule = strtoupper((string) ($issue['rule'] ?? 'UNKNOWN'));
            $severity = strtolower((string) ($issue['severity'] ?? 'info'));

            $byRule[$rule] = ($byRule[$rule] ?? 0) + 1;
            $bySeverity[$severity] = ($bySeverity[$severity] ?? 0) + 1;
            ++$total;
        }
    }

    ksort($byRule);

    return ['total' => $total, 'by_rule' => $byRule, 'by_severity' => $bySeverity];
};

// --------------------------------------------------------------------- inputs ---

$manifestRaw = (string) file_get_contents($manifestPath);
$manifest = json_decode($manifestRaw, true);
if (!is_array($manifest)) {
    fwrite(STDERR, 'Manifest is not valid JSON: ' . $manifestPath . PHP_EOL);
    exit(2);
}

$defaults = is_array($manifest['defaults'] ?? null) ? $manifest['defaults'] : [];
$targets = is_array($manifest['targets'] ?? null) ? $manifest['targets'] : [];

if ($targets === []) {
    fwrite(STDERR, 'Manifest lists no targets.' . PHP_EOL);
    exit(2);
}

$binary = $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'quality-check';
if (!is_file($binary)) {
    fwrite(STDERR, 'Cannot find bin/quality-check; run this from a clone.' . PHP_EOL);
    exit(2);
}

$timeout = max(30, (int) (getenv('BENCHMARK_TIMEOUT') ?: 900));

echo PHP_EOL . 'Benchmark: finding counts over your projects' . PHP_EOL;
echo '  manifest: ' . $manifestPath . PHP_EOL;
echo '  targets:  ' . count($targets) . PHP_EOL;
echo '  flags:    --only=custom --tier=security --fail-on=none --no-cache' . PHP_EOL;
echo PHP_EOL;

$measured = [];
$outputDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-benchmark-' . bin2hex(random_bytes(4));
@mkdir($outputDir, 0777, true);

register_shutdown_function(static function () use ($outputDir): void {
    if (!is_dir($outputDir)) {
        return;
    }
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($outputDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($outputDir);
});

foreach ($targets as $index => $target) {
    if (!is_array($target)) {
        $fail('target #' . $index . ' is not an object');
        continue;
    }

    $name = (string) ($target['name'] ?? ('target-' . $index));
    if (($target['enabled'] ?? true) === false) {
        $note($name . ': skipped (enabled=false)');
        continue;
    }

    $path = (string) ($target['path'] ?? '');
    if ($path === '') {
        $fail($name . ': no path');
        continue;
    }
    if (!is_dir($path)) {
        $fail($name . ': not a directory: ' . $path);
        continue;
    }

    $tier = (string) ($target['tier'] ?? $defaults['tier'] ?? 'security');
    $minConfidence = (string) ($target['min_confidence'] ?? $defaults['min_confidence'] ?? 'low');

    $targetOut = $outputDir . DIRECTORY_SEPARATOR . 't' . $index;
    @mkdir($targetOut, 0777, true);

    $command = [
        PHP_BINARY,
        $binary,
        $path,
        '--only=custom',
        '--tier=' . $tier,
        '--min-confidence=' . $minConfidence,
        // Findings must never fail a benchmark run; a non-zero exit here is a
        // crash, not a quality verdict.
        '--fail-on=none',
        // A warm cache would report the previous run's counts, which is the one
        // thing a benchmark must never do.
        '--no-cache',
        '--format=json',
        '--output=' . $targetOut,
    ];

    $result = $run($command, $root, $timeout);

    if ($result['code'] === 124) {
        $fail($name . ': timed out after ' . $timeout . 's');
        continue;
    }

    $reportPath = $targetOut . DIRECTORY_SEPARATOR . 'quality-report.json';
    if (!is_file($reportPath)) {
        $fail(
            $name . ': no report written (exit ' . $result['code'] . ')'
            . ($result['stderr'] !== '' ? ' — ' . trim(substr($result['stderr'], -200)) : '')
        );
        continue;
    }

    $summary = $summarize($reportPath);
    $measured[$name] = $summary;

    printf(
        '  %-28s %5d finding(s)  [%d C / %d E / %d W / %d I]',
        $name,
        $summary['total'],
        $summary['by_severity']['critical'],
        $summary['by_severity']['error'],
        $summary['by_severity']['warning'],
        $summary['by_severity']['info']
    );
    echo PHP_EOL;
}

if ($measured === []) {
    echo PHP_EOL . 'Nothing was measured.' . PHP_EOL;
    exit($failures === [] ? 1 : 2);
}

// --------------------------------------------------------------- per-rule view ---

echo PHP_EOL . 'Findings by rule' . PHP_EOL;

$ruleTotals = [];
foreach ($measured as $summary) {
    foreach ($summary['by_rule'] as $rule => $count) {
        $ruleTotals[$rule] = ($ruleTotals[$rule] ?? 0) + $count;
    }
}
arsort($ruleTotals);

$width = 0;
foreach (array_keys($ruleTotals) as $rule) {
    $width = max($width, strlen((string) $rule));
}

foreach ($ruleTotals as $rule => $count) {
    printf('  %-' . $width . 's %6d', (string) $rule, $count);
    echo PHP_EOL;
}

$grandTotal = array_sum($ruleTotals);
echo PHP_EOL . '  ' . str_pad('total', $width) . ' ' . sprintf('%6d', $grandTotal) . PHP_EOL;

// The number that decides whether a rule earns its place: a rule responsible for
// most of a project's findings is noise until proven otherwise.
if ($grandTotal > 0) {
    echo PHP_EOL . 'Share of all findings' . PHP_EOL;
    $ranked = $ruleTotals;
    arsort($ranked);
    $shown = 0;
    foreach ($ranked as $rule => $count) {
        $share = 100 * $count / $grandTotal;
        if ($share < 5.0 && $shown > 0) {
            break;
        }
        printf('  %-' . $width . 's %6.1f%%', (string) $rule, $share);
        echo PHP_EOL;
        ++$shown;
    }
}

// ------------------------------------------------------------------- baseline ---

$baselinePayload = [
    'generated_by' => 'tools/benchmark-projects.php',
    // Stamped from the same source the reports use, so a baseline can be tied
    // to the analyzer code that produced it. A baseline with no version is one
    // nobody can reason about when the counts move.
    'package_version' => PackageVersion::detect($root),
    'targets' => $measured,
];

if ($baselinePath !== null) {
    // Refuse to overwrite without --update, and do not write at all in that
    // case: overwriting the baseline is how a real regression gets recorded as
    // the new normal, and it must be a deliberate act.
    if (is_file($baselinePath) && !$update) {
        $fail($baselinePath . ' already exists; pass --update to overwrite it');
    } elseif (@file_put_contents($baselinePath, json_encode($baselinePayload, JSON_PRETTY_PRINT)) === false) {
        $fail('could not write baseline: ' . $baselinePath);
    } else {
        $note('baseline written: ' . $baselinePath);
    }
}

if ($diffPath !== null) {
    $previous = json_decode((string) @file_get_contents($diffPath), true);
    if (!is_array($previous['targets'] ?? null)) {
        $fail('baseline is not readable: ' . $diffPath);
    } else {
        echo PHP_EOL . 'Drift against ' . $diffPath . PHP_EOL;
        $drift = 0;

        foreach ($measured as $name => $summary) {
            $before = $previous['targets'][$name] ?? null;
            if (!is_array($before)) {
                $note($name . ': new target, not in the baseline');
                continue;
            }

            $delta = $summary['total'] - (int) ($before['total'] ?? 0);
            if ($delta === 0) {
                $note($name . ': unchanged (' . $summary['total'] . ')');
                continue;
            }

            ++$drift;
            printf(
                '  %-28s %+d  (%d -> %d)',
                $name,
                $delta,
                (int) ($before['total'] ?? 0),
                $summary['total']
            );
            echo PHP_EOL;
            if (!empty($previous['package_version'])) {
                echo '      baseline was measured against ' . (string) $previous['package_version'] . PHP_EOL;
            }

            $moved = [];
            foreach ($summary['by_rule'] as $rule => $count) {
                $was = (int) ($before['by_rule'][$rule] ?? 0);
                if ($count !== $was) {
                    $moved[] = $rule . ' ' . ($count - $was > 0 ? '+' : '') . ($count - $was);
                }
            }
            foreach ((array) ($before['by_rule'] ?? []) as $rule => $was) {
                if (!isset($summary['by_rule'][$rule])) {
                    $moved[] = $rule . ' -' . $was;
                }
            }
            foreach ($moved as $move) {
                echo '      ' . $move . PHP_EOL;
            }
        }

        if ($drift === 0) {
            $note('no drift');
        }
    }
}

echo PHP_EOL;
echo $failures === []
    ? 'Benchmark completed.'
    : 'Benchmark completed with ' . count($failures) . ' failure(s).';

echo PHP_EOL;

exit($failures === [] ? 0 : 1);
