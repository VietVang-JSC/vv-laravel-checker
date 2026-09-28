<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Reporters;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

/**
 * Confidence-weighted quality score.
 *
 * Raw counts lie: 137 medium-confidence Blade echoes or 170 missing-test
 * hints would nuke any naive Critical x 10 formula. Every finding contributes
 * severity-weight x confidence-weight, so only high-confidence severe
 * findings move the needle — and only those can block the release gate.
 */
final class QualityScore
{
    private const SEVERITY_WEIGHTS = [
        'critical' => 10.0,
        'error' => 5.0,
        'warning' => 2.0,
        'info' => 0.5,
    ];

    private const CONFIDENCE_WEIGHTS = [
        'high' => 1.0,
        'medium' => 0.5,
        'low' => 0.25,
    ];

    /**
     * Rule substrings per dimension, checked in order. Anything unmatched
     * lands in Laravel Best Practices.
     *
     * @var array<string, list<string>>
     */
    private const DIMENSIONS = [
        'Security' => [
            'OWASP_', 'UNSAFE_', 'INSECURE_', 'HARDCODED_SECRET', 'MASS_ASSIGNMENT',
            'SQL_INJECTION', 'SESSION_FIXATION', 'DISABLED_CSRF', 'CVE', 'GHSA',
            'COMPOSER_ADVISOR', 'VULNERAB',
        ],
        'Database' => ['MIGRATION_'],
        'Testability' => ['MISSING_', 'COVERAGE', 'TEST_'],
        'Maintainability' => ['DEAD_CODE', 'NAMING_CONVENTION', 'TODO_FIXME', 'CONVENTION'],
        'Reliability' => ['ROUTE_MISSING_VALIDATION', 'LARAVEL_PITFALL'],
        'Laravel Best Practices' => [],
    ];

    /**
     * @param CheckResult[] $results
     * @return array{overall: int, gate: string, dimensions: array<string, array{score: int, findings: int}>, must_fix: int, review: int, tech_debt: int, top_must_fix: list<array{rule: string, count: int}>}
     */
    public static function score(array $results): array
    {
        $deductions = [];
        $findings = [];
        $mustFixRules = [];
        $mustFix = 0;
        $review = 0;
        $techDebt = 0;

        foreach (self::DIMENSIONS as $dimension => $_) {
            $deductions[$dimension] = 0.0;
            $findings[$dimension] = 0;
        }

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }
                $dimension = self::dimensionFor($issue->rule, $result->name);
                ++$findings[$dimension];
                $deductions[$dimension] += self::SEVERITY_WEIGHTS[$issue->severity->value]
                    * self::CONFIDENCE_WEIGHTS[$issue->confidence->value];

                $bucket = self::bucketFor($issue, $dimension);
                if ($bucket === 'must_fix') {
                    ++$mustFix;
                    $mustFixRules[$issue->rule] = ($mustFixRules[$issue->rule] ?? 0) + 1;
                } elseif ($bucket === 'review') {
                    ++$review;
                } else {
                    ++$techDebt;
                }
            }
        }

        $dimensions = [];
        $total = 0;
        foreach ($deductions as $dimension => $deduction) {
            $score = (int) max(0, round(100 - $deduction));
            $dimensions[$dimension] = ['score' => $score, 'findings' => $findings[$dimension]];
            $total += $score;
        }

        arsort($mustFixRules);
        $top = [];
        foreach (array_slice($mustFixRules, 0, 5, true) as $rule => $count) {
            $top[] = ['rule' => $rule, 'count' => $count];
        }

        return [
            'overall' => (int) round($total / max(1, count($deductions))),
            'gate' => $mustFix > 0 ? 'BLOCKED' : 'PASS',
            'dimensions' => $dimensions,
            'must_fix' => $mustFix,
            'review' => $review,
            'tech_debt' => $techDebt,
            'top_must_fix' => $top,
        ];
    }

    private static function dimensionFor(string $rule, string $checker): string
    {
        if (in_array($checker, ['composer_audit', 'trivy'], true)) {
            return 'Security';
        }
        $upper = strtoupper($rule);
        foreach (self::DIMENSIONS as $dimension => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($upper, $needle)) {
                    return $dimension;
                }
            }
        }

        return 'Laravel Best Practices';
    }

    /**
     * @return 'must_fix'|'review'|'tech_debt'
     */
    private static function bucketFor(Issue $issue, string $dimension): string
    {
        if ($issue->severity === Severity::Critical) {
            return 'must_fix';
        }
        if (
            $dimension === 'Security'
            && $issue->severity === Severity::Error
            && $issue->confidence === Confidence::High
        ) {
            return 'must_fix';
        }
        if ($dimension === 'Security') {
            return 'review';
        }

        return 'tech_debt';
    }

    public static function severityWeight(Severity $severity): float
    {
        return self::SEVERITY_WEIGHTS[$severity->value];
    }

    public static function confidenceWeight(Confidence $confidence): float
    {
        return self::CONFIDENCE_WEIGHTS[$confidence->value];
    }
}
