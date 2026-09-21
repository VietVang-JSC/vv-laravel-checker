<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;

/**
 * Aggregates issues across all checker results into grouped statistics, used by
 * every reporter so the breakdown is consistent (JSON, Markdown, console, HTML).
 */
final class IssueGrouper
{
    /**
     * Group issues by rule id across all results.
     *
     * @param CheckResult[] $results
     * @return list<array{rule: string, source: string, count: int, critical: int, error: int, warning: int, info: int}>
     */
    public static function byRule(array $results): array
    {
        $map = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }
                $key = $issue->source . '|' . $issue->rule;
                if (!isset($map[$key])) {
                    $map[$key] = [
                        'rule' => $issue->rule,
                        'source' => $issue->source,
                        'count' => 0,
                        'critical' => 0,
                        'error' => 0,
                        'warning' => 0,
                        'info' => 0,
                    ];
                }
                $map[$key]['count']++;
                $map[$key][$issue->severity->value]++;
            }
        }

        $list = array_values($map);
        usort($list, static fn (array $a, array $b): int => $b['count'] <=> $a['count']);

        return $list;
    }

    /**
     * Group by OWASP category for the dedicated OWASP section.
     *
     * @param CheckResult[] $results
     * @return array<string, int> rule => count
     */
    public static function owaspByRule(array $results): array
    {
        $out = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if ($issue instanceof Issue && str_starts_with($issue->rule, 'OWASP_')) {
                    $out[$issue->rule] = ($out[$issue->rule] ?? 0) + 1;
                }
            }
        }
        arsort($out);

        return $out;
    }
}
