<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * Shadow-mode store for v0.6.1 ownership decisions (no Issue objects).
 * The analyzer records one OwnershipDecision per sensitive controller
 * action; drivers dump the sidecar report; production scans ignore it.
 * Explicit reset() — static state must never leak between runs/tests.
 */
final class OwnershipShadow
{
    /** @var list<OwnershipDecision> */
    private static array $decisions = [];

    public static function reset(): void
    {
        self::$decisions = [];
    }

    public static function record(OwnershipDecision $decision): void
    {
        self::$decisions[] = $decision;
    }

    /**
     * @return list<OwnershipDecision>
     */
    public static function all(): array
    {
        return self::$decisions;
    }

    /**
     * @return array<string, int> status => count
     */
    public static function counts(): array
    {
        $out = [
            OwnershipDecision::PROTECTED => 0,
            OwnershipDecision::REVIEW => 0,
            OwnershipDecision::EXPOSED => 0,
            OwnershipDecision::UNKNOWN => 0,
        ];
        foreach (self::$decisions as $decision) {
            $out[$decision->status] = ($out[$decision->status] ?? 0) + 1;
        }

        return $out;
    }
}
