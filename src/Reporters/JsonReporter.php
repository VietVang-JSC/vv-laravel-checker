<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class JsonReporter implements ReporterInterface
{
    public function render(array $results, CheckContext $ctx): void
    {
        $payload = [
            'schema_version' => 1,
            'generated_at' => (new \DateTimeImmutable())->format('Y-m-d\TH:i:sP'),
            'package_version' => $ctx->packageVersion,
            'exit_code' => $ctx->exitCode,
            'overall_status' => $this->overallStatus($results),
            'tier' => $ctx->tier,
            'fail_on' => $ctx->failOn,
            'min_confidence' => $ctx->minConfidence,
            'duration_total' => $this->totalDuration($results),
            'summary' => $this->buildSummary($results),
            'rules' => IssueGrouper::byRule($results),
            'owasp' => $this->buildOwasp($results),
            'checkers' => $this->buildCheckers($results),
        ];

        if (!is_dir($ctx->outputDir) && !@mkdir($ctx->outputDir, 0777, true) && !is_dir($ctx->outputDir)) {
            return;
        }

        file_put_contents(
            $ctx->outputDir . DIRECTORY_SEPARATOR . 'quality-report.json',
            json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL
        );
    }

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
                'duration' => round($result->duration, 3),
                'summary' => $result->summary,
                'issues' => array_map(static fn (Issue $issue): array => $issue->toArray(), $result->issues),
            ];
        }

        return $checkers;
    }

    private function buildOwasp(array $results): array
    {
        $mapping = [
            'OWASP_BROKEN_ACCESS_CONTROL' => 'A01 Broken Access Control',
            'OWASP_SSRF' => 'A10 SSRF',
            'OWASP_SSTI' => 'A03 Injection (SSTI)',
            'OWASP_MISCONFIGURATION' => 'A05 Security Misconfiguration',
            'OWASP_COMMAND_INJECTION' => 'A03 Injection (Command)',
            'OWASP_XXE' => 'A05 XXE',
            'OWASP_PATH_TRAVERSAL' => 'A01 Path Traversal',
            'OWASP_OPEN_REDIRECT' => 'A07 Open Redirect',
            'OWASP_FILE_UPLOAD' => 'A08 File Upload',
        ];

        $categories = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }
                if (!isset($mapping[$issue->rule])) {
                    continue;
                }
                $category = $mapping[$issue->rule];
                $categories[$category] = ($categories[$category] ?? 0) + 1;
            }
        }

        return ['categories' => $categories, 'total' => array_sum($categories)];
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

    /**
     * @param CheckResult[] $results
     */
    private function totalDuration(array $results): float
    {
        $total = 0.0;
        foreach ($results as $result) {
            if ($result instanceof CheckResult) {
                $total += $result->duration;
            }
        }

        return round($total, 3);
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

            if ($result->status === 'passed') {
                ++$summary['passed'];
            } elseif (in_array($result->status, ['failed', 'error', 'warning'], true)) {
                ++$summary['failed'];
            } elseif ($result->status === 'skipped') {
                ++$summary['skipped'];
            }

            $summary['total_issues'] += count($result->issues);
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }
                if ($issue->severity === Severity::Critical) {
                    ++$summary['critical'];
                } elseif ($issue->severity === Severity::Error) {
                    ++$summary['error'];
                } elseif ($issue->severity === Severity::Warning) {
                    ++$summary['warning'];
                } else {
                    ++$summary['info'];
                }
            }
        }

        return $summary;
    }
}
