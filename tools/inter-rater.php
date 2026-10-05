<?php

/**
 * Inter-rater agreement (Cohen's kappa) for 8/10.
 *
 * Two reviewers label the same 50 sampled findings as TP/FP independently.
 * This script compares their CSVs and prints kappa. Target for 8/10 is >=0.9.
 *
 * Each CSV is the output of tools/sample-findings.php plus two columns:
 *   verdict (TP/FP) and notes — or a minimal CSV with: sample_id,verdict
 *
 * Usage:
 *   php tools/inter-rater.php reviewer1.csv reviewer2.csv
 *   php tools/inter-rater.php --demo  # demo with 48/50 agreement (kappa 0.92)
 */

declare(strict_types=1);

// phpcs:ignoreFile Generic.Files.OneObjectStructurePerFile.Found

if (in_array('--demo', $argv, true)) {
    $n = 50;
    $agree = 48;
    $po = $agree / $n;
    $pe = 0.5;
    $kappa = ($po - $pe) / (1 - $pe);
    echo "demo n=$n agree=$agree po=" . number_format($po, 3) . " kappa=" . number_format($kappa, 3) . PHP_EOL;
    // @phpstan-ignore greaterOrEqual.alwaysTrue
    echo ($kappa >= 0.9 ? "PASS" : "FAIL") . " — threshold 0.9\n";
    // @phpstan-ignore greaterOrEqual.alwaysTrue
    exit($kappa >= 0.9 ? 0 : 1);
}

if ($argc < 3) {
    fwrite(STDERR, "Usage: php tools/inter-rater.php <reviewer1.csv> <reviewer2.csv>\n");
    fwrite(STDERR, "  CSV must have sample_id and verdict (TP/FP) columns.\n");
    fwrite(STDERR, "  Use --demo for a 48/50 demo.\n");
    exit(2);
}

/**
 * @return array<string, string>
 */
function loadVerdicts(string $path): array
{
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false || $lines === []) {
        fwrite(STDERR, "Cannot read: $path\n");
        exit(2);
    }
    $header = str_getcsv(array_shift($lines));
    $idxId = array_search('sample_id', $header, true);
    $idxVerdict = array_search('verdict', $header, true);
    if ($idxId === false || $idxVerdict === false) {
        fwrite(STDERR, "CSV $path missing sample_id or verdict column\n");
        exit(2);
    }
    $out = [];
    foreach ($lines as $line) {
        if (trim($line) === '') {
            continue;
        }
        $row = str_getcsv($line);
        $id = trim($row[$idxId] ?? '');
        $v = strtoupper(trim($row[$idxVerdict] ?? ''));
        if ($id === '' || ($v !== 'TP' && $v !== 'FP')) {
            continue;
        }
        $out[$id] = $v;
    }

    return $out;
}

$a = loadVerdicts($argv[1]);
$b = loadVerdicts($argv[2]);

$ids = array_intersect(array_keys($a), array_keys($b));
$n = count($ids);
if ($n === 0) {
    fwrite(STDERR, "No overlapping sample_id between files\n");
    exit(2);
}

$agree = 0;
$tpBoth = 0;
$fpBoth = 0;
$tpA = 0;
$tpB = 0;
foreach ($ids as $id) {
    if ($a[$id] === $b[$id]) {
        $agree++;
    }
    if ($a[$id] === 'TP') {
        $tpA++;
    }
    if ($b[$id] === 'TP') {
        $tpB++;
    }
    if ($a[$id] === 'TP' && $b[$id] === 'TP') {
        $tpBoth++;
    }
    if ($a[$id] === 'FP' && $b[$id] === 'FP') {
        $fpBoth++;
    }
}

$po = $agree / $n;
// Pe = P(TP by chance) + P(FP by chance) = (tpA/n)*(tpB/n) + (fpA/n)*(fpB/n)
$fpA = $n - $tpA;
$fpB = $n - $tpB;
$pe = ($tpA / $n) * ($tpB / $n) + ($fpA / $n) * ($fpB / $n);
$kappa = $pe >= 1 ? 0 : ($po - $pe) / (1 - $pe);

echo "n=$n agree=$agree po=" . number_format($po, 3) . " pe=" . number_format($pe, 3) . " kappa=" . number_format($kappa, 3) . PHP_EOL;
echo "TP both=$tpBoth FP both=$fpBoth\n";
echo ($kappa >= 0.9 ? "PASS" : "FAIL") . " — threshold 0.9 for 8/10\n";
exit($kappa >= 0.9 ? 0 : 1);
