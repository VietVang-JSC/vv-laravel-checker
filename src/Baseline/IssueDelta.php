<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Baseline;

/**
 * PR-style delta: which current findings are new, which baseline entries
 * got fixed, and how many carry over. Signatures come from
 * BaselineManager (rule|file|line|message), so moved lines count as
 * new+fixed — documented trade-off, same as the baseline filter itself.
 */
final class IssueDelta
{
    /**
     * @param list<array<string, mixed>> $issueArrays current findings as arrays
     * @param array<string, string> $baselineSignatures loaded baseline (signature => signature)
     * @return array{new: list<array<string, mixed>>, fixed: int, existing: int, new_by_rule: array<string, int>}
     */
    public static function compute(array $issueArrays, array $baselineSignatures): array
    {
        $manager = new BaselineManager();

        $new = [];
        $newByRule = [];
        $matched = [];
        foreach ($issueArrays as $issue) {
            if (!is_array($issue)) {
                continue;
            }
            $sig = $manager->signature($issue);
            if ($sig !== null && isset($baselineSignatures[$sig])) {
                $matched[$sig] = true;
                continue;
            }
            $new[] = $issue;
            $rule = isset($issue['rule']) && is_string($issue['rule']) ? $issue['rule'] : 'unknown';
            $newByRule[$rule] = ($newByRule[$rule] ?? 0) + 1;
        }

        $fixed = 0;
        foreach ($baselineSignatures as $sig => $_) {
            if (!isset($matched[$sig])) {
                ++$fixed;
            }
        }
        arsort($newByRule);

        return [
            'new' => $new,
            'fixed' => $fixed,
            'existing' => count($matched),
            'new_by_rule' => $newByRule,
        ];
    }
}
