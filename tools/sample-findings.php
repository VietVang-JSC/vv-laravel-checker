<?php

/**
 * Sample 100 findings from a quality-report.json for external precision review.
 *
 * The 6/10 gate pins precision on the 220-case labeled corpus (internal).
 * 7/10 requires an *external* precision: sample real findings from real
 * projects, have a human label each as TP/FP, compute precision per rule.
 *
 * This script is the sampler. It takes the JSON report produced by
 *   php bin/quality-check /path/to/project --format=json --output=/tmp/out
 * and prints a CSV + per-rule breakdown that a reviewer can label.
 *
 * No network, no project list ships with the package — the reviewer runs it
 * on their own report.
 *
 * Usage:
 *   php tools/sample-findings.php <quality-report.json> [--n=100] [--seed=42] [--out=sample.csv]
 *   php tools/sample-findings.php <quality-report.json> --n=100 --seed=42 | head -20
 *
 * Output CSV columns: sample_id,rule,severity,confidence,file,line,message
 * Per-rule breakdown is printed to STDERR so CSV on STDOUT stays clean.
 */

declare(strict_types=1);

$reportPath = null;
$sampleN = 100;
$seed = 42;
$outPath = null;

foreach (array_slice($argv, 1) as $arg) {
    if (str_starts_with($arg, '--n=')) {
        $sampleN = max(1, (int) substr($arg, 4));
        continue;
    }
    if (str_starts_with($arg, '--seed=')) {
        $seed = (int) substr($arg, 7);
        continue;
    }
    if (str_starts_with($arg, '--out=')) {
        $outPath = substr($arg, 6);
        continue;
    }
    if (!str_starts_with($arg, '--') && $reportPath === null) {
        $reportPath = $arg;
        continue;
    }
    fwrite(STDERR, 'Unknown argument: ' . $arg . PHP_EOL);
    exit(2);
}

if ($reportPath === null) {
    fwrite(STDERR, <<<TXT
Usage: php tools/sample-findings.php <quality-report.json> [--n=100] [--seed=42] [--out=sample.csv]

  quality-report.json  JSON report from --format=json
  --n=100             how many findings to sample (default 100)
  --seed=42           PRNG seed for reproducible sample
  --out=FILE          also write CSV to FILE (otherwise STDOUT)

TXT);
    exit(2);
}

if (!is_file($reportPath)) {
    fwrite(STDERR, 'Report not found: ' . $reportPath . PHP_EOL);
    exit(2);
}

$payload = json_decode((string) file_get_contents($reportPath), true);
if (!is_array($payload)) {
    fwrite(STDERR, 'Report is not valid JSON: ' . $reportPath . PHP_EOL);
    exit(2);
}

// Flatten issues from the report shape used by this package:
// { checkers: [ { name, issues: [ {rule,file,line,message,severity,confidence} ] } ] }
// Support also a flat { issues: [...] } shape for forward compat.
$issues = [];
foreach ($payload['checkers'] ?? [] as $checker) {
    foreach ($checker['issues'] ?? [] as $issue) {
        $issues[] = [
            'rule' => strtoupper((string) ($issue['rule'] ?? 'UNKNOWN')),
            'severity' => strtolower((string) ($issue['severity'] ?? 'info')),
            'confidence' => strtolower((string) ($issue['confidence'] ?? 'low')),
            'file' => (string) ($issue['file'] ?? ''),
            'line' => $issue['line'] ?? '',
            'message' => (string) ($issue['message'] ?? ''),
            'source' => (string) ($issue['source'] ?? ($checker['name'] ?? '')),
        ];
    }
}
if ($issues === [] && isset($payload['issues']) && is_array($payload['issues'])) {
    foreach ($payload['issues'] as $issue) {
        if (!is_array($issue)) {
            continue;
        }
        $issues[] = [
            'rule' => strtoupper((string) ($issue['rule'] ?? 'UNKNOWN')),
            'severity' => strtolower((string) ($issue['severity'] ?? 'info')),
            'confidence' => strtolower((string) ($issue['confidence'] ?? 'low')),
            'file' => (string) ($issue['file'] ?? ''),
            'line' => $issue['line'] ?? '',
            'message' => (string) ($issue['message'] ?? ''),
            'source' => (string) ($issue['source'] ?? ''),
        ];
    }
}

$total = count($issues);
if ($total === 0) {
    fwrite(STDERR, "No issues found in report — nothing to sample.\n");
    exit(0);
}

// Deterministic shuffle with seed
mt_srand($seed);
for ($i = $total - 1; $i > 0; $i--) {
    $j = mt_rand(0, $i);
    $tmp = $issues[$i];
    $issues[$i] = $issues[$j];
    $issues[$j] = $tmp;
}

$n = min($sampleN, $total);
$sample = array_slice($issues, 0, $n);

// Per-rule breakdown (full report vs sample)
$byRuleFull = [];
foreach ($issues as $iss) {
    $byRuleFull[$iss['rule']] = ($byRuleFull[$iss['rule']] ?? 0) + 1;
}
arsort($byRuleFull);

$byRuleSample = [];
foreach ($sample as $iss) {
    $byRuleSample[$iss['rule']] = ($byRuleSample[$iss['rule']] ?? 0) + 1;
}
arsort($byRuleSample);

fwrite(STDERR, sprintf("Sampled %d of %d findings (seed=%d) from %s\n", $n, $total, $seed, $reportPath));
fwrite(STDERR, "Full report by rule:\n");
foreach ($byRuleFull as $rule => $cnt) {
    $pct = 100 * $cnt / $total;
    fwrite(STDERR, sprintf("  %-30s %4d (%4.1f%%)\n", $rule, $cnt, $pct));
}
fwrite(STDERR, "Sample by rule:\n");
foreach ($byRuleSample as $rule => $cnt) {
    fwrite(STDERR, sprintf("  %-30s %4d\n", $rule, $cnt));
}
fwrite(STDERR, "Review columns to add: verdict (TP/FP), notes\n");
fwrite(STDERR, "Precision = TP / (TP+FP) per rule and overall; target for 7/10 is >=0.85 per high rule.\n");

// CSV
$header = ['sample_id', 'rule', 'severity', 'confidence', 'file', 'line', 'message'];
$rows = [];
$rows[] = $header;
foreach ($sample as $idx => $iss) {
    $rows[] = [
        (string) ($idx + 1),
        $iss['rule'],
        $iss['severity'],
        $iss['confidence'],
        $iss['file'],
        (string) $iss['line'],
        str_replace(["\r", "\n"], ' ', $iss['message']),
    ];
}

$csv = '';
foreach ($rows as $row) {
    $escaped = array_map(static function (string $v): string {
        if (str_contains($v, ',') || str_contains($v, '"') || str_contains($v, "\n")) {
            return '"' . str_replace('"', '""', $v) . '"';
        }
        return $v;
    }, $row);
    $csv .= implode(',', $escaped) . "\n";
}

if ($outPath !== null) {
    if (@file_put_contents($outPath, $csv) === false) {
        fwrite(STDERR, 'Could not write: ' . $outPath . PHP_EOL);
        exit(1);
    }
    fwrite(STDERR, 'CSV written to: ' . $outPath . PHP_EOL);
}
echo $csv;
