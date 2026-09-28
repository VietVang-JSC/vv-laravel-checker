<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

/**
 * Minimal explainability trace: source → propagation → sanitizer/guard →
 * sink. Analyzers attach it as finding metadata so reports (and reviewers)
 * can answer WHY a finding exists, not just WHERE.
 *
 * Deliberately small: an ordered list of labeled steps with file lines.
 * No CFG, no interprocedural reasoning — that lives in future layers.
 */
final class FlowTrace
{
    /** @var list<array{kind: string, detail: string, line: int|null}> */
    private array $steps = [];

    public function source(string $detail, ?int $line = null): self
    {
        $this->steps[] = ['kind' => 'source', 'detail' => $detail, 'line' => $line];

        return $this;
    }

    public function propagate(string $detail, ?int $line = null): self
    {
        $this->steps[] = ['kind' => 'propagation', 'detail' => $detail, 'line' => $line];

        return $this;
    }

    public function guard(string $detail, ?int $line = null): self
    {
        $this->steps[] = ['kind' => 'guard', 'detail' => $detail, 'line' => $line];

        return $this;
    }

    public function sink(string $detail, ?int $line = null): self
    {
        $this->steps[] = ['kind' => 'sink', 'detail' => $detail, 'line' => $line];

        return $this;
    }

    public function isEmpty(): bool
    {
        return $this->steps === [];
    }

    /**
     * @return list<array{kind: string, detail: string, line: int|null}>
     */
    public function toMetadata(): array
    {
        return $this->steps;
    }

    public function describe(): string
    {
        $parts = [];
        foreach ($this->steps as $step) {
            $at = $step['line'] !== null ? ' @' . $step['line'] : '';
            $parts[] = $step['kind'] . ': ' . $step['detail'] . $at;
        }

        return implode(' -> ', $parts);
    }
}
