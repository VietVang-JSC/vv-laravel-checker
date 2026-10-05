<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Reporters;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\PackageVersion;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Remediation\RuleRemediation;
use Rampart\QualityChecker\Runner\CheckContext;

final class MarkdownReporter implements ReporterInterface
{
    public function render(array $results, CheckContext $ctx): void
    {
        $generatedAt = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $version = $ctx->packageVersion;
        $summary = $this->buildSummary($results);

        $lines = [];
        $lines[] = '# Laravel Quality Report';
        $lines[] = '';
        $lines[] = '<div align="center">';
        $lines[] = '';
        $lines[] = '*🛡️ Comprehensive quality gate for Laravel — security, tests & conventions*';
        $lines[] = '';
        $lines[] = '</div>';
        $lines[] = '';
        $lines[] = 'Generated: `' . $generatedAt . '` | Package: `' . PackageVersion::label($version) . '` | Tier: `' . $this->esc($ctx->tier) . '` | Fail on: `' . $this->esc($ctx->failOn) . '` | Exit: `' . $ctx->exitCode . '`';
        $lines[] = '';
        $lines[] = '**Status:** ' . $this->overallStatus($results, $ctx->failOn)
            . ' | **Tier:** ' . $this->esc($ctx->tier)
            . ' | **Fail on:** ' . $this->esc($ctx->failOn)
            . ' | **Exit code:** ' . $ctx->exitCode;
        $lines[] = '';
        $lines[] = $this->badgeLine($summary);
        $lines[] = '';
        $lines[] = $this->overviewBadges($summary);
        $lines[] = '';
        $lines[] = '## Contents';
        $lines[] = '';
        $lines[] = '- [Summary](#summary)';
        $lines[] = '- [Risk Overview](#risk-overview)';
        $lines[] = '- [Action Plan](#action-plan)';
        $lines[] = '- [Top Rules](#top-rules)';
        $lines[] = '- [OWASP](#owasp)';
        $lines[] = '- [Remediation](#remediation)';
        $lines[] = '- [Per-Checker](#per-checker)';
        $lines[] = '- [Issues](#issues)';
        foreach ($results as $result) {
            if ($result instanceof CheckResult) {
                $lines[] = '  - [' . $this->esc($result->name) . '](#' . $this->slug($result->name) . ')';
            }
        }
        $lines[] = '';
        $lines[] = '## Summary';
        $lines[] = '';
        $lines[] = '| Metric | Value |';
        $lines[] = '|---|---|';
        $lines[] = '| Checkers | ' . $summary['checkers'] . ' |';
        $lines[] = '| Passed | ' . $summary['passed'] . ' |';
        $lines[] = '| Failed | ' . $summary['failed'] . ' |';
        $lines[] = '| Skipped | ' . $summary['skipped'] . ' |';
        $lines[] = '| Total Issues | ' . $summary['total_issues'] . ' |';
        $lines[] = '| Critical | ' . $summary['critical'] . ' |';
        $lines[] = '| Error | ' . $summary['error'] . ' |';
        $lines[] = '| Warning | ' . $summary['warning'] . ' |';
        $lines[] = '| Info | ' . $summary['info'] . ' |';
        $lines[] = '| P0 — fix before release | ' . $summary['p0'] . ' |';
        $lines[] = '| P1 — fix this sprint | ' . $summary['p1'] . ' |';
        $lines[] = '| P2 — engineering improvement | ' . $summary['p2'] . ' |';
        $lines[] = '| P3 — technical debt / backlog | ' . $summary['p3'] . ' |';
        $lines[] = '';
        $lines[] = $this->mermaidSeverityChart($summary);
        $lines[] = '';
        $lines[] = '## Risk Overview';
        $lines[] = '';
        $lines[] = '| Category | Findings | Highest | Action |';
        $lines[] = '|---|---|---|---|';
        foreach (QualityScore::riskOverview($results) as $row) {
            $lines[] = '| ' . $row['category'] . ' | ' . $row['findings'] . ' | ' . $row['highest'] . ' | ' . $row['action'] . ' |';
        }
        $lines[] = '';
        $lines[] = '## Action Plan';
        $lines[] = '';
        $lines[] = 'Priority is scheduling urgency, not severity.';
        $lines[] = '';
        $lines[] = '| Priority | Meaning | Mapping | Findings |';
        $lines[] = '|---|---|---|---|';
        foreach (QualityScore::priorityLegend() as $entry) {
            $lines[] = '| ' . $entry['level'] . ' | ' . $entry['title'] . ' | ' . $entry['rule']
                . ' | ' . $summary[strtolower($entry['level'])] . ' |';
        }
        $lines[] = '';

        $rules = IssueGrouper::byRule($results);
        if (count($rules) > 0) {
            $lines[] = '## Top Rules';
            $lines[] = '';
            $lines[] = '| Rule | Source | Critical | Error | Warning | Info | Total |';
            $lines[] = '|---|---|---|---|---|---|---|';
            foreach (array_slice($rules, 0, 50) as $r) {
                $lines[] = sprintf(
                    '| %s | %s | %d | %d | %d | %d | %d |',
                    $this->esc($r['rule']),
                    $this->esc($r['source']),
                    $r['critical'],
                    $r['error'],
                    $r['warning'],
                    $r['info'],
                    $r['count']
                );
            }
            if (count($rules) > 50) {
                $lines[] = '';
                $lines[] = '_Showing top 50 of ' . count($rules) . ' rules. See the JSON report for the full list._';
            }
            $lines[] = '';
        }

        $owasp = $this->owaspCounts($results);
        if (count($owasp) > 0) {
            $lines[] = '## OWASP';
            $lines[] = '';
            $lines[] = '| Rule | Count |';
            $lines[] = '|---|---|';
            foreach ($owasp as $rule => $count) {
                $lines[] = '| ' . $this->esc($rule) . ' | ' . $count . ' |';
            }
            $lines[] = '';
        }

        foreach ($this->remediationBlocks($results) as $block) {
            $lines[] = $block;
        }

        $lines[] = '## Per-Checker';
        $lines[] = '';
        $lines[] = '| Checker | Status | Critical | Error | Warning | Info | Duration |';
        $lines[] = '|---|---|---|---|---|---|---|';

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            $lines[] = sprintf(
                '| %s | %s | %d | %d | %d | %d | %.2fs |',
                $this->esc($result->name),
                $this->esc($result->status),
                $this->countBySeverity($result, Severity::Critical),
                $this->countBySeverity($result, Severity::Error),
                $this->countBySeverity($result, Severity::Warning),
                $this->countBySeverity($result, Severity::Info),
                $result->duration
            );
        }

        $lines[] = '';

        $lines[] = '## Issues';
        $lines[] = '';

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            $issueCount = count($result->issues);
            $lines[] = '## ' . $this->esc($result->name);
            $lines[] = '';
            $lines[] = 'Status: **' . $this->esc($result->status) . '** — ' . $issueCount . ' issue(s)';

            if ($result->summary !== null && $result->summary !== '') {
                $lines[] = '';
                $lines[] = $this->esc($result->summary);
            }

            if ($issueCount === 0) {
                $lines[] = '';
                $lines[] = 'No issues found.';
                $lines[] = '';
                continue;
            }

            $lines[] = '';
            $lines[] = '<details>';
            $lines[] = '<summary>Show issues for <strong>' . $this->esc($result->name) . '</strong> (' . $issueCount . ')</summary>';
            $lines[] = '';

            foreach ($this->groupByFile($result) as $file => $issues) {
                $lines[] = '### `' . $this->esc($file) . '`';
                $lines[] = '';
                $lines[] = '| Rule | Priority | Severity | Confidence | Line | Message |';
                $lines[] = '|---|---|---|---|---|---|';

                foreach ($issues as $issue) {
                    $lines[] = sprintf(
                        '| %s | %s | %s | %s | %s | %s |',
                        $this->esc($issue['rule']),
                        $this->esc($issue['priority']),
                        $this->esc($issue['severity']),
                        $this->esc($issue['confidence']),
                        $this->esc($issue['line'] !== null ? (string) $issue['line'] : '-'),
                        $this->esc($issue['message'])
                    );
                }

                $lines[] = '';
            }

            $lines[] = '</details>';
            $lines[] = '';
        }

        $outputDir = $ctx->outputDir;
        if (!is_dir($outputDir) && !@mkdir($outputDir, 0777, true) && !is_dir($outputDir)) {
            return;
        }

        file_put_contents($outputDir . DIRECTORY_SEPARATOR . 'quality-report.md', implode("\n", $lines));
    }

    private function badgeLine(array $summary): string
    {
        return sprintf(
            '![Quality](https://img.shields.io/badge/quality-%s-%s) | Issues: %d | Critical: %d',
            urlencode($this->overallStatusForBadge($summary)),
            $this->badgeColor($summary),
            $summary['total_issues'],
            $summary['critical']
        );
    }

    private function overallStatusForBadge(array $summary): string
    {
        if ($summary['critical'] > 0) {
            return 'critical';
        }
        if ($summary['error'] > 0) {
            return 'failed';
        }
        if ($summary['warning'] > 0) {
            return 'warning';
        }

        return 'passed';
    }

    private function badgeColor(array $summary): string
    {
        if ($summary['critical'] > 0 || $summary['error'] > 0) {
            return 'red';
        }
        if ($summary['warning'] > 0) {
            return 'orange';
        }

        return 'brightgreen';
    }

    private function countBySeverity(CheckResult $result, Severity $severity): int
    {
        $count = 0;
        foreach ($result->issues as $issue) {
            if ($issue->severity === $severity) {
                ++$count;
            }
        }

        return $count;
    }

    private function groupByFile(CheckResult $result): array
    {
        $groups = [];
        foreach ($result->issues as $issue) {
            $file = $issue->file ?? '(no file)';
            $groups[$file][] = [
                'rule' => $issue->rule,
                'priority' => QualityScore::priorityFor(
                    $issue->rule,
                    $result->name,
                    $issue->severity->value,
                    $issue->confidence->value
                ),
                'severity' => $issue->severity->value,
                'confidence' => $issue->confidence->value,
                'file' => $file,
                'line' => $issue->line,
                'message' => $issue->message,
            ];
        }

        ksort($groups);

        return $groups;
    }

    /**
     * One remediation block per rule present in the report, so every level of
     * developer sees what the finding means and how to fix it.
     *
     * @param list<CheckResult> $results
     * @return list<string>
     */
    private function remediationBlocks(array $results): array
    {
        $rules = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                $rules[$issue->rule] = true;
            }
        }

        if ($rules === []) {
            return [];
        }

        $lines = ['## Remediation', ''];
        foreach (array_keys($rules) as $rule) {
            $entry = RuleRemediation::for($rule);
            if ($entry === null) {
                continue;
            }
            $lines[] = '### `' . $rule . '`';
            $lines[] = '';
            $lines[] = $entry['why'];
            $lines[] = '';
            $lines[] = '```php';
            $lines[] = $entry['fix'];
            $lines[] = '```';
            $lines[] = '';
            if ($entry['docs'] !== null) {
                $lines[] = '_See `docs/false-positives.md` (' . $entry['docs'] . ') for details._';
                $lines[] = '';
            }
        }

        return $lines;
    }

    /**
     * @return array<string, int>
     */
    private function owaspCounts(array $results): array
    {
        $counts = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (str_starts_with($issue->rule, 'OWASP_')) {
                    $counts[$issue->rule] = ($counts[$issue->rule] ?? 0) + 1;
                }
            }
        }

        ksort($counts);

        return $counts;
    }

    private function buildSummary(array $results): array
    {
        $summary = [
            'checkers' => count($results),
            'passed' => 0,
            'failed' => 0,
            'skipped' => 0,
            'total_issues' => 0,
            'critical' => 0,
            'error' => 0,
            'warning' => 0,
            'info' => 0,
            'p0' => 0,
            'p1' => 0,
            'p2' => 0,
            'p3' => 0,
        ];

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $status = $result->status;
            if ($status === 'passed') {
                ++$summary['passed'];
            } elseif ($status === 'failed' || $status === 'error' || $status === 'warning') {
                ++$summary['failed'];
            } elseif ($status === 'skipped') {
                ++$summary['skipped'];
            }

            $summary['total_issues'] += count($result->issues);
            foreach ($result->issues as $issue) {
                $severity = $issue->severity;
                if ($severity === Severity::Critical) {
                    ++$summary['critical'];
                } elseif ($severity === Severity::Error) {
                    ++$summary['error'];
                } elseif ($severity === Severity::Warning) {
                    ++$summary['warning'];
                } else {
                    ++$summary['info'];
                }
                ++$summary[strtolower(QualityScore::priorityFor(
                    $issue->rule,
                    $result->name,
                    $issue->severity->value,
                    $issue->confidence->value
                ))];
            }
        }

        return $summary;
    }

    private function overallStatus(array $results, string $failOn): string
    {
        $failed = false;
        $hasIssues = false;

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            if ($result->status === 'failed' || $result->status === 'error') {
                $failed = true;
            }
            if (count($result->issues) > 0) {
                $hasIssues = true;
            }
        }

        // With fail-on=none the gate never fails: report completion with
        // findings instead of a contradictory "failed" status.
        if (strtolower($failOn) === 'none') {
            return $hasIssues ? 'completed' : 'passed';
        }
        if ($failed) {
            return 'failed';
        }
        if ($hasIssues) {
            return 'warning';
        }

        return 'passed';
    }

    private function esc(string $value): string
    {
        return str_replace(['|', "\n"], ['\\|', ' '], $value);
    }

    /**
     * GitHub-compatible heading anchor: lowercase, spaces to hyphens,
     * keep letters/digits/underscores/hyphens.
     */
    private function slug(string $value): string
    {
        $slug = strtolower($value);
        $slug = str_replace(' ', '-', $slug);

        return (string) preg_replace('/[^a-z0-9_-]+/', '', $slug);
    }

    /**
     * @param array<string, int> $summary
     */
    private function overviewBadges(array $summary): string
    {
        $parts = [];
        $parts[] = '![Checkers](https://img.shields.io/badge/checkers-' . $summary['checkers'] . '-blue)';
        $parts[] = '![Passed](https://img.shields.io/badge/passed-' . $summary['passed'] . '-brightgreen)';
        if ($summary['failed'] > 0) {
            $parts[] = '![Failed](https://img.shields.io/badge/failed-' . $summary['failed'] . '-red)';
        }
        if ($summary['skipped'] > 0) {
            $parts[] = '![Skipped](https://img.shields.io/badge/skipped-' . $summary['skipped'] . '-lightgrey)';
        }
        $parts[] = '![P0](https://img.shields.io/badge/P0-' . $summary['p0'] . '-critical)';
        $parts[] = '![P1](https://img.shields.io/badge/P1-' . $summary['p1'] . '-orange)';

        return implode(' ', $parts);
    }

    /**
     * @param array<string, int> $summary
     */
    private function mermaidSeverityChart(array $summary): string
    {
        $total = max(1, $summary['total_issues']);
        if ($total === 1 && $summary['total_issues'] === 0) {
            return '_No issues — clean._';
        }
        $lines = [
            '```mermaid',
            'pie showData',
            '    title Severity distribution',
        ];
        foreach (['critical' => 'Critical', 'error' => 'Error', 'warning' => 'Warning', 'info' => 'Info'] as $k => $label) {
            $cnt = (int) ($summary[$k] ?? 0);
            if ($cnt > 0) {
                $lines[] = sprintf('    "%s %d" : %d', $label, $cnt, $cnt);
            }
        }
        $lines[] = '```';

        return implode("\n", $lines);
    }
}
