<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

/**
 * A proven-constant string value with its provenance chain. Only
 * exact values exist — anything not proven constant resolves to null
 * (no ConstantValue at all), never to a guess.
 */
final class ConstantValue
{
    /**
     * @param list<array{kind: string, detail: string, file: string|null, line: int|null}> $provenance
     */
    public function __construct(
        public readonly string $value,
        public readonly string $confidence = 'exact',
        public readonly array $provenance = [],
    ) {
    }

    /**
     * @param array{kind: string, detail: string, file: string|null, line: int|null} $step
     */
    public function withStep(array $step): self
    {
        return new self($this->value, $this->confidence, [...$this->provenance, $step]);
    }
}
