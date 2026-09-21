<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Baseline;

/**
 * Filters baselined issues out of checker results.
 *
 * Given `CheckResult[]` and a `BaselineManager`, returns the same results with
 * baselined issues removed from each result's `issues` list but flagged as
 * `metadata['baselined'] = true` so reporting can still show them. New issues
 * are left untouched.
 *
 * Status handling (assumes CheckResult exposes a mutable public `status` string
 * and public `issues` array):
 *  - If a result had issues but ALL of them were baselined, its status becomes
 *    'passed' (only known issues remain => nothing to fail on).
 *  - If at least one non-baselined issue remains, the status is unchanged.
 *  - Results with no issues are untouched.
 *
 * Assumptions:
 *  - Works against the Phase 1 `CheckResult` object shape: public `status`
 *    (string) and public `issues` (array of associative Issue arrays).
 *  - Issue arrays are keyed by `rule`, `file`, `line`, `message` for signature
 *    generation (see BaselineManager).
 */
final class BaselineFilter
{
    private BaselineManager $manager;

    private int $baselinedCount = 0;

    public function __construct(BaselineManager $manager)
    {
        $this->manager = $manager;
    }

    /**
     * Remove baselined issues from results.
     *
     * Accepts either CheckResult objects (with public `issues` / `status`) or
     * plain array results (`['name' => ..., 'issues' => [...], 'status' => ...]`),
     * and returns the results in the same shape it received them.
     *
     * @param array $results CheckResult[] or list<array<string, mixed>>
     * @return array
     */
    public function filter(array $results): array
    {
        $this->baselinedCount = 0;

        foreach ($results as &$result) {
            $issues = $this->issueList($result);
            if ($issues === null) {
                continue;
            }

            $kept = [];
            $anyBaselined = false;

            foreach ($issues as $issue) {
                if (!is_array($issue)) {
                    $kept[] = $issue;
                    continue;
                }
                if ($this->manager->isBaselined($issue)) {
                    $this->baselinedCount++;
                    $anyBaselined = true;
                    $issue['metadata'] = array_merge($issue['metadata'] ?? [], ['baselined' => true]);
                    $issue['baselined'] = true;
                    continue;
                }
                $kept[] = $issue;
            }

            $this->setIssues($result, $kept);

            if ($anyBaselined && count($kept) === 0) {
                $this->setStatus($result, 'passed');
            }
        }
        unset($result);

        return $results;
    }

    /**
     * Number of issues that were identified as baselined by the last filter() call.
     */
    public function countBaselined(): int
    {
        return $this->baselinedCount;
    }

    private function issueList(mixed $result): ?array
    {
        if (is_array($result)) {
            return isset($result['issues']) && is_array($result['issues']) ? $result['issues'] : null;
        }

        if (is_object($result)) {
            return isset($result->issues) && is_array($result->issues) ? $result->issues : null;
        }

        return null;
    }

    private function setIssues(mixed &$result, array $issues): void
    {
        if (is_array($result)) {
            $result['issues'] = $issues;

            return;
        }

        if (is_object($result)) {
            $result->issues = $issues;
        }
    }

    private function setStatus(mixed &$result, string $status): void
    {
        if (is_array($result)) {
            $result['status'] = $status;

            return;
        }

        if (is_object($result)) {
            $result->status = $status;
        }
    }
}
