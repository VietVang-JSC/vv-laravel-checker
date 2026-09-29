<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * Negative evidence trail: what a check looked for, what it found,
 * what stayed unresolved, and what is missing — plus the conclusion
 * drawn from them. Shared by every rule so findings prove negative
 * decisions ("I looked for A, B, C and found none") instead of merely
 * asserting them.
 *
 * Dynamic or unsupported shapes are always `unresolved`, never
 * `missing`: absence of proof is not proof of absence.
 */
final class EvidenceTrail
{
    public const FOUND = 'found';

    public const MISSING = 'missing';

    public const UNRESOLVED = 'unresolved';

    /** @var list<array{check: string, status: string, detail: string}> */
    private array $checks = [];

    private string $conclusion = '';

    public function found(string $check, string $detail = ''): self
    {
        return $this->record($check, self::FOUND, $detail);
    }

    public function missing(string $check, string $detail = ''): self
    {
        return $this->record($check, self::MISSING, $detail);
    }

    public function unresolved(string $check, string $detail = ''): self
    {
        return $this->record($check, self::UNRESOLVED, $detail);
    }

    public function conclude(string $conclusion): self
    {
        $this->conclusion = $conclusion;

        return $this;
    }

    /**
     * @return array{checks: list<array{check: string, status: string, detail: string}>, conclusion: string}
     */
    public function toArray(): array
    {
        return ['checks' => $this->checks, 'conclusion' => $this->conclusion];
    }

    private function record(string $check, string $status, string $detail): self
    {
        $this->checks[] = ['check' => $check, 'status' => $status, 'detail' => $detail];

        return $this;
    }
}
