<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\TableSeparator;
use Symfony\Component\Console\Output\OutputInterface;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Remediation\RuleRemediation;
use VietVang\QualityChecker\Runner\CheckContext;

final class ConsoleReporter implements ReporterInterface
{
    private const MAX_ISSUES_PER_CHECKER = 50;

    private OutputInterface $output;

    public function __construct(OutputInterface $output)
    {
        $this->output = $output;
    }

    public function render(array $results, CheckContext $ctx): void
    {
        if ($ctx->quiet) {
            $this->renderSummaryLine($results);

            return;
        }

        $this->output->writeln('');
        $this->output->writeln('<fg=cyan>Laravel Quality Checker</> <options=bold>v' . $ctx->packageVersion . '</>');
        $this->output->writeln('Generated: ' . (new \DateTimeImmutable())->format('Y-m-d H:i:s'));
        $this->output->writeln(sprintf(
            'Tier: %s | Fail-on: %s | Min-confidence: %s',
            $ctx->tier,
            $ctx->failOn,
            $ctx->minConfidence
        ));
        $this->output->writeln('');

        $table = new Table($this->output);
        $table->setHeaders(['Checker', 'Status', 'Critical', 'Error', 'Warning', 'Info', 'Duration', 'Summary']);

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $table->addRow([
                $result->name,
                $this->statusTag($result->status),
                (string) $this->countBySeverity($result, Severity::Critical),
                (string) $this->countBySeverity($result, Severity::Error),
                (string) $this->countBySeverity($result, Severity::Warning),
                (string) $this->countBySeverity($result, Severity::Info),
                sprintf('%.2fs', $result->duration),
                $result->summary ?? '',
            ]);
        }

        $table->addRow(new TableSeparator());
        $summary = $this->buildSummary($results);
        $table->addRow([
            '<options=bold>TOTAL</>',
            '',
            (string) $summary['critical'],
            (string) $summary['error'],
            (string) $summary['warning'],
            (string) $summary['info'],
            '',
            sprintf(
                '%d checker(s), %d passed, %d failed, %d skipped',
                $summary['checkers'],
                $summary['passed'],
                $summary['failed'],
                $summary['skipped']
            ),
        ]);

        $table->render();

        $this->output->writeln('');
        if ($ctx->exitCode === 0) {
            $this->output->writeln('<fg=green>✔ All checks passed.</>');
        } else {
            $this->output->writeln('<fg=red>✘ Quality gate not met. Exit code: ' . $ctx->exitCode . '</>');
            $this->output->writeln('<fg=gray>Tip: re-run with --format=json for machine-readable details, or --fail-on=none to review without failing.</>');
        }

        $this->printOwaspFindings($results);
        $this->printTopRules($results);
        $this->printIssues($results);
        $this->printRemediation($results);
    }

    private function renderSummaryLine(array $results): void
    {
        $summary = $this->buildSummary($results);

        $this->output->writeln(sprintf(
            'quality-checker: %d checker(s) | %d passed | %d failed | %d skipped | issues: %d (critical %d, error %d)',
            $summary['checkers'],
            $summary['passed'],
            $summary['failed'],
            $summary['skipped'],
            $summary['total_issues'],
            $summary['critical'],
            $summary['error']
        ));
    }

    private function printIssues(array $results): void
    {
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            if (count($result->issues) === 0) {
                continue;
            }

            $this->output->writeln('');
            $this->output->writeln('<fg=yellow>Issues — ' . $result->name . ':</>');

            $shown = 0;
            foreach ($this->groupByFile($result) as $file => $issues) {
                $this->output->writeln('  <options=bold>' . $file . '</>');

                foreach ($issues as $issue) {
                    if ($shown >= self::MAX_ISSUES_PER_CHECKER) {
                        break 2;
                    }
                    ++$shown;

                    $location = $issue->line !== null ? ':' . $issue->line : '';

                    $this->output->writeln(sprintf(
                        '    %s [%s] %s%s — %s (%s)',
                        $this->severityTag($issue->severity),
                        $issue->rule,
                        $file,
                        $location,
                        $issue->message,
                        $issue->confidence->value
                    ));
                }
            }

            $remaining = count($result->issues) - $shown;
            if ($remaining > 0) {
                $this->output->writeln(sprintf(
                    '  … and %d more issue(s) — see the JSON report for the full list.',
                    $remaining
                ));
            }
        }
    }

    /**
     * Per-rule fix guidance so junior developers see what to do, not just
     * what was found. Full code samples live in the HTML/JSON/Markdown reports.
     *
     * @param CheckResult[] $results
     */
    private function printRemediation(array $results): void
    {
        $rules = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if ($issue instanceof Issue) {
                    $rules[$issue->rule] = true;
                }
            }
        }

        if ($rules === []) {
            return;
        }

        $this->output->writeln('');
        $this->output->writeln('<fg=cyan>Remediation (cách sửa theo rule):</>');

        foreach (array_keys($rules) as $rule) {
            $entry = RuleRemediation::for($rule);
            if ($entry === null) {
                continue;
            }
            $this->output->writeln(sprintf('  <options=bold>[%s]</> %s', $rule, $entry['why_vi']));
        }

        $this->output->writeln('  Code mẫu sửa đúng: quality-report.html / .md / .json (mục remediation).');
    }

    /**
     * @return array<string, Issue[]>
     */
    private function groupByFile(CheckResult $result): array
    {
        $groups = [];
        foreach ($result->issues as $issue) {
            if (!$issue instanceof Issue) {
                continue;
            }
            $groups[$issue->file ?? '(project)'][] = $issue;
        }

        ksort($groups);

        return $groups;
    }

    /**
     * @param CheckResult[] $results
     */
    private function printTopRules(array $results): void
    {
        $rules = IssueGrouper::byRule($results);
        if (count($rules) === 0) {
            return;
        }

        $this->output->writeln('');
        $this->output->writeln('<fg=cyan>Top rules (nhóm lỗi theo rule):</>');
        $table = new Table($this->output);
        $table->setHeaders(['Rule', 'Source', 'Critical', 'Error', 'Warning', 'Info', 'Total']);
        foreach (array_slice($rules, 0, 20) as $r) {
            $table->addRow([
                $r['rule'],
                $r['source'],
                (string) $r['critical'],
                (string) $r['error'],
                (string) $r['warning'],
                (string) $r['info'],
                (string) $r['count'],
            ]);
        }
        $table->render();
    }

    private function printOwaspFindings(array $results): void
    {
        $counts = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if ($issue instanceof Issue && str_starts_with($issue->rule, 'OWASP_')) {
                    $counts[$issue->rule] = ($counts[$issue->rule] ?? 0) + 1;
                }
            }
        }

        if (count($counts) === 0) {
            return;
        }

        ksort($counts);

        $this->output->writeln('');
        $this->output->writeln('<fg=red>OWASP Findings:</>');

        foreach ($counts as $rule => $count) {
            $this->output->writeln(sprintf(
                '  %s: %d',
                $rule,
                $count
            ));
        }
    }

    private function statusTag(string $status): string
    {
        return match ($status) {
            'passed' => '<fg=green>' . $status . '</>',
            'failed', 'error' => '<fg=red>' . $status . '</>',
            'warning' => '<fg=yellow>' . $status . '</>',
            'skipped' => '<fg=gray>' . $status . '</>',
            default => $status,
        };
    }

    private function severityTag(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '<fg=red;options=bold>critical</>',
            Severity::Error => '<fg=red>error</>',
            Severity::Warning => '<fg=yellow>warning</>',
            Severity::Info => '<fg=cyan>info</>',
        };
    }

    private function countBySeverity(CheckResult $result, Severity $severity): int
    {
        $count = 0;
        foreach ($result->issues as $issue) {
            if ($issue instanceof Issue && $issue->severity === $severity) {
                ++$count;
            }
        }

        return $count;
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
