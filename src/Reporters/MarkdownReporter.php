<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class MarkdownReporter implements ReporterInterface
{
    public function render(array $results, CheckContext $ctx): void
    {
        $generatedAt = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $version = $ctx->packageVersion ?? '0.0.0';
        $summary = $this->buildSummary($results);

        $lines = [];
        $lines[] = '# Laravel Quality Report';
        $lines[] = '';
        $lines[] = 'Generated: ' . $generatedAt . ' | Package: v' . $version;
        $lines[] = '';
        $lines[] = '**Status:** ' . $this->overallStatus($results);
        $lines[] = '';
        $lines[] = $this->badgeLine($summary);
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
        $lines[] = '';

        $rules = IssueGrouper::byRule($results);
        if (count($rules) > 0) {
            $lines[] = '## Top Rules / Nhóm lỗi theo rule';
            $lines[] = '';
            $lines[] = '| Rule | Source | Critical | Error | Warning | Info | Total |';
            $lines[] = '|---|---|---|---|---|---|---|';
            foreach ($rules as $r) {
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

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            $lines[] = '## ' . $this->esc($result->name);
            $lines[] = '';
            $lines[] = 'Status: **' . $this->esc($result->status) . '**';

            if ($result->summary !== null && $result->summary !== '') {
                $lines[] = '';
                $lines[] = $this->esc($result->summary);
            }

            if (count($result->issues) === 0) {
                $lines[] = '';
                $lines[] = 'No issues found.';
                $lines[] = '';
                continue;
            }

            $lines[] = '';
            $lines[] = '| Rule | Severity | Confidence | Location | Message |';
            $lines[] = '|---|---|---|---|---|';

            foreach ($this->groupByFile($result) as $file => $issues) {
                foreach ($issues as $issue) {
                    $location = $issue['file'] . ':' . ($issue['line'] ?? '-');
                    $lines[] = sprintf(
                        '| %s | %s | %s | `%s` | %s |',
                        $this->esc($issue['rule']),
                        $this->esc($issue['severity']),
                        $this->esc($issue['confidence']),
                        $this->esc($location),
                        $this->esc($issue['message'])
                    );
                }
            }

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
            }
        }

        return $summary;
    }

    private function overallStatus(array $results): string
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
}
