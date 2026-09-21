<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;

final class Deduplicator
{
    /**
     * Remove duplicate issues within each result, keeping the one with the
     * highest confidence (ties keep the first occurrence).
     *
     * @param CheckResult[] $results
     * @return CheckResult[]
     */
    public function dedupe(array $results): array
    {
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $result->issues = $this->dedupeList($result->issues);
        }

        return $results;
    }

    /**
     * @param Issue[] $issues
     * @return Issue[]
     */
    public function dedupeList(array $issues): array
    {
        $seen = [];
        $kept = [];

        foreach ($issues as $issue) {
            if (!$issue instanceof Issue) {
                $kept[] = $issue;
                continue;
            }

            $sig = $issue->signature();
            $previous = $seen[$sig] ?? null;

            if ($previous === null) {
                $seen[$sig] = $issue;
                $kept[] = $issue;
                continue;
            }

            if ($issue->confidence->intValue() > $previous->confidence->intValue()) {
                $index = array_search($previous, $kept, true);
                if ($index !== false) {
                    $kept[$index] = $issue;
                }
                $seen[$sig] = $issue;
            }
        }

        return array_values($kept);
    }
}
