<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class HtmlReporter implements ReporterInterface
{
    private const CSS = <<<'CSS'
    :root {
        --critical: #b91c1c;
        --error: #dc2626;
        --warning: #d97706;
        --info: #2563eb;
        --pass: #16a34a;
        --border: #e5e7eb;
        --bg: #ffffff;
        --muted: #6b7280;
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        padding: 24px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #111827;
        background: #f9fafb;
        line-height: 1.5;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        padding: 20px 24px;
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        margin-bottom: 24px;
    }
    h1 { margin: 0; font-size: 22px; }
    .meta { color: var(--muted); font-size: 13px; }
    .meta span { margin-right: 16px; }
    .badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 9999px;
        color: #fff;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge.passed { background: var(--pass); }
    .badge.warning { background: var(--warning); }
    .badge.failed { background: var(--error); }
    h2 { font-size: 18px; margin: 0 0 12px; }
    .card {
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    th { background: #f3f4f6; font-weight: 600; }
    .status { font-weight: 600; }
    .status.passed { color: var(--pass); }
    .status.warning { color: var(--warning); }
    .status.failed { color: var(--error); }
    .status.skipped, .status.error { color: var(--muted); }
    .severity { font-weight: 600; }
    .severity.critical { color: var(--critical); }
    .severity.error { color: var(--error); }
    .severity.warning { color: var(--warning); }
    .severity.info { color: var(--info); }
    .rule { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
    .file { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; color: var(--muted); }
    .summary-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 8px; }
    .stat {
        flex: 1 1 120px;
        padding: 14px;
        border: 1px solid var(--border);
        border-radius: 8px;
        text-align: center;
        background: #f9fafb;
    }
    .stat .value { font-size: 26px; font-weight: 700; }
    .stat .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .checker-section { margin-bottom: 32px; }
    .checker-head { margin-bottom: 12px; }
    .issue-group-title { font-weight: 600; font-size: 14px; margin: 18px 0 8px; }
    .skipped-hint { color: var(--muted); font-style: italic; }
    .empty { color: var(--muted); }
    CSS;

    /**
     * @param CheckResult[] $results
     */
    public function render(array $results, CheckContext $ctx): void
    {
        $html = $this->buildDocument($results, $ctx);

        $outputDir = $ctx->outputDir;
        if (!is_dir($outputDir) && !@mkdir($outputDir, 0777, true) && !is_dir($outputDir)) {
            return;
        }

        file_put_contents($outputDir . DIRECTORY_SEPARATOR . 'quality-report.html', $html);
    }

    /**
     * @param CheckResult[] $results
     */
    private function buildDocument(array $results, CheckContext $ctx): string
    {
        $checkers = $this->buildCheckers($results);
        $summary = $this->buildSummary($results);

        return '<!DOCTYPE html>' . "\n"
            . '<html lang="en">' . "\n"
            . $this->buildHead()
            . '<body>' . "\n"
            . '<div class="container">' . "\n"
            . $this->buildHeader($ctx, $this->overallStatus($results))
            . $this->buildSummaryGrid($summary)
            . $this->buildRulesTable($results)
            . $this->buildOwaspTable($results)
            . $this->buildCheckerTable($checkers)
            . $this->buildIssueSections($checkers)
            . '</div>' . "\n"
            . '</body>' . "\n"
            . '</html>' . "\n";
    }

    private function buildHead(): string
    {
        return '<head>' . "\n"
            . '<meta charset="utf-8">' . "\n"
            . '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n"
            . '<title>Laravel Quality Report</title>' . "\n"
            . '<style>' . "\n"
            . self::CSS . "\n"
            . '</style>' . "\n"
            . '</head>' . "\n";
    }

    private function buildHeader(CheckContext $ctx, string $status): string
    {
        return '<header>' . "\n"
            . '<div>' . "\n"
            . '<h1>Laravel Quality Report</h1>' . "\n"
            . '<div class="meta">' . "\n"
            . '<span>Generated: ' . $this->escape((new \DateTimeImmutable())->format('Y-m-d\TH:i:sP')) . '</span>' . "\n"
            . '<span>Package: v' . $this->escape($ctx->packageVersion) . '</span>' . "\n"
            . '<span>Tier: ' . $this->escape($ctx->tier) . '</span>' . "\n"
            . '<span>Exit code: ' . $this->escape((string) $ctx->exitCode) . '</span>' . "\n"
            . '<span>Output: ' . $this->escape($ctx->outputDir) . '</span>' . "\n"
            . '</div>' . "\n"
            . '</div>' . "\n"
            . '<span class="badge ' . $this->escape($status) . '">' . $this->escape($status) . '</span>' . "\n"
            . '</header>' . "\n";
    }

    /**
     * @param array<string, int> $summary
     */
    private function buildSummaryGrid(array $summary): string
    {
        return '<div class="card">' . "\n"
            . '<h2>Summary</h2>' . "\n"
            . '<div class="summary-grid">' . "\n"
            . $this->stat('Checkers', (int) ($summary['checkers'] ?? 0))
            . $this->stat('Passed', (int) ($summary['passed'] ?? 0))
            . $this->stat('Failed', (int) ($summary['failed'] ?? 0))
            . $this->stat('Skipped', (int) ($summary['skipped'] ?? 0))
            . $this->stat('Total Issues', (int) ($summary['total_issues'] ?? 0))
            . $this->stat('Critical', (int) ($summary['critical'] ?? 0))
            . $this->stat('Error', (int) ($summary['error'] ?? 0))
            . $this->stat('Warning', (int) ($summary['warning'] ?? 0))
            . $this->stat('Info', (int) ($summary['info'] ?? 0))
            . '</div>' . "\n"
            . '</div>' . "\n";
    }

    private function stat(string $label, int $value): string
    {
        return '<div class="stat"><div class="value">' . (string) $value . '</div>'
            . '<div class="label">' . $this->escape($label) . '</div></div>' . "\n";
    }

    /**
     * @param CheckResult[] $results
     */
    private function buildRulesTable(array $results): string
    {
        $rules = IssueGrouper::byRule($results);
        if (count($rules) === 0) {
            return '';
        }

        $rows = '<thead><tr>'
            . '<th>Rule</th><th>Source</th><th>Critical</th><th>Error</th><th>Warning</th><th>Info</th><th>Total</th>'
            . '</tr></thead>' . "\n<tbody>\n";
        foreach (array_slice($rules, 0, 50) as $r) {
            $rows .= '<tr>'
                . '<td class="rule">' . $this->escape($r['rule']) . '</td>'
                . '<td>' . $this->escape($r['source']) . '</td>'
                . '<td>' . (int) $r['critical'] . '</td>'
                . '<td>' . (int) $r['error'] . '</td>'
                . '<td>' . (int) $r['warning'] . '</td>'
                . '<td>' . (int) $r['info'] . '</td>'
                . '<td><strong>' . (int) $r['count'] . '</strong></td>'
                . '</tr>' . "\n";
        }
        $rows .= '</tbody>';

        return '<div class="card">' . "\n"
            . '<h2>Top Rules / Nhóm lỗi theo rule</h2>' . "\n"
            . '<table>' . $rows . '</table>' . "\n"
            . '</div>' . "\n";
    }

    /**
     * @param CheckResult[] $results
     */
    private function buildOwaspTable(array $results): string
    {
        $counts = $this->owaspCounts($results);

        $html = '<div class="card">' . "\n"
            . '<h2>OWASP</h2>' . "\n";

        if ($counts === []) {
            $html .= '<p class="empty">No OWASP findings.</p>' . "\n";
        } else {
            $html .= '<table>' . "\n"
                . '<thead>' . "\n"
                . '<tr><th>Rule</th><th>Count</th></tr>' . "\n"
                . '</thead>' . "\n"
                . '<tbody>' . "\n";
            foreach ($counts as $rule => $count) {
                $html .= '<tr><td class="rule">' . $this->escape($rule) . '</td><td>' . (string) $count . '</td></tr>' . "\n";
            }
            $html .= '</tbody>' . "\n"
                . '</table>' . "\n";
        }

        return $html . '</div>' . "\n";
    }

    /**
     * @param array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}}> $checkers
     */
    private function buildCheckerTable(array $checkers): string
    {
        $html = '<div class="card">' . "\n"
            . '<h2>Per-Checker</h2>' . "\n"
            . '<table>' . "\n"
            . '<thead>' . "\n"
            . '<tr><th>Checker</th><th>Status</th><th>Critical</th><th>Error</th><th>Warning</th><th>Info</th><th>Duration</th></tr>' . "\n"
            . '</thead>' . "\n"
            . '<tbody>' . "\n";

        foreach ($checkers as $result) {
            $html .= '<tr>'
                . '<td>' . $this->escape($result['name']) . '</td>'
                . '<td class="status ' . $this->escape($result['status']) . '">' . $this->escape($result['status']) . '</td>'
                . '<td>' . (string) $result['counts']['critical'] . '</td>'
                . '<td>' . (string) $result['counts']['error'] . '</td>'
                . '<td>' . (string) $result['counts']['warning'] . '</td>'
                . '<td>' . (string) $result['counts']['info'] . '</td>'
                . '<td>' . number_format($result['duration'], 2) . 's</td>'
                . '</tr>' . "\n";
        }

        return $html . '</tbody>' . "\n"
            . '</table>' . "\n"
            . '</div>' . "\n";
    }

    /**
     * @param array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}, files: array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>}> $checkers
     */
    private function buildIssueSections(array $checkers): string
    {
        $html = '';

        foreach ($checkers as $result) {
            $html .= '<div class="card checker-section">' . "\n"
                . '<div class="checker-head">' . "\n"
                . '<h2>' . $this->escape($result['name']) . '</h2>' . "\n"
                . '<span class="status ' . $this->escape($result['status']) . '">' . $this->escape($result['status']) . '</span>' . "\n"
                . '</div>' . "\n";

            if ($result['summary'] !== null && $result['summary'] !== '') {
                $html .= '<p>' . $this->escape($result['summary']) . '</p>' . "\n";
            }

            if ($result['files'] === []) {
                $html .= '<p class="empty">No issues found.</p>' . "\n";
            } else {
                foreach ($result['files'] as $file => $issues) {
                    $html .= $this->buildIssueTable($file, $issues);
                }
            }

            $html .= '</div>' . "\n";
        }

        return $html;
    }

    /**
     * @param list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}> $issues
     */
    private function buildIssueTable(string $file, array $issues): string
    {
        $html = '<div class="issue-group">' . "\n"
            . '<div class="issue-group-title">' . $this->escape($file) . '</div>' . "\n"
            . '<table>' . "\n"
            . '<thead>' . "\n"
            . '<tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Line</th><th>Message</th></tr>' . "\n"
            . '</thead>' . "\n"
            . '<tbody>' . "\n";

        foreach ($issues as $issue) {
            $html .= '<tr>'
                . '<td class="rule">' . $this->escape($issue['rule']) . '</td>'
                . '<td class="severity ' . $this->escape($issue['severity']) . '">' . $this->escape($issue['severity']) . '</td>'
                . '<td>' . $this->escape($issue['confidence']) . '</td>'
                . '<td>' . $this->escape($issue['line'] !== null ? (string) $issue['line'] : '-') . '</td>'
                . '<td>' . $this->escape($issue['message']) . '</td>'
                . '</tr>' . "\n";
        }

        return $html . '</tbody>' . "\n"
            . '</table>' . "\n"
            . '</div>' . "\n";
    }

    private function escape(mixed $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * @param CheckResult[] $results
     * @return array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}, files: array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>}>
     */
    private function buildCheckers(array $results): array
    {
        $checkers = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $checkers[] = [
                'name' => $result->name,
                'status' => $result->status,
                'duration' => $result->duration,
                'summary' => $result->summary,
                'counts' => [
                    'critical' => $this->countBySeverity($result, Severity::Critical),
                    'error' => $this->countBySeverity($result, Severity::Error),
                    'warning' => $this->countBySeverity($result, Severity::Warning),
                    'info' => $this->countBySeverity($result, Severity::Info),
                ],
                'files' => $this->groupByFile($result),
            ];
        }

        return $checkers;
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

    /**
     * @return array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>
     */
    private function groupByFile(CheckResult $result): array
    {
        $groups = [];
        foreach ($result->issues as $issue) {
            $file = $issue->file ?? '(no file)';
            $groups[$file][] = [
                'rule' => $issue->rule,
                'severity' => $issue->severity->value,
                'confidence' => $issue->confidence->value,
                'line' => $issue->line,
                'message' => $issue->message,
            ];
        }

        ksort($groups);

        return $groups;
    }

    /**
     * @param CheckResult[] $results
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

    /**
     * @param CheckResult[] $results
     * @return array<string, int>
     */
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

    /**
     * @param CheckResult[] $results
     */
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
}
