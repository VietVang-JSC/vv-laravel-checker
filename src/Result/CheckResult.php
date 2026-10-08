<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Result;

final class CheckResult
{
    /**
     * @param Issue[] $issues
     */
    public function __construct(
        public string $name,
        public string $status,
        public float $duration,
        public array $issues,
        public ?string $rawOutput,
        public ?string $summary,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'status' => $this->status,
            'duration' => $this->duration,
            'issues' => array_map(static fn (Issue $issue): array => $issue->toArray(), $this->issues),
            'raw_output' => $this->rawOutput,
            'summary' => $this->summary,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $issues = [];
        foreach (($data['issues'] ?? []) as $issueData) {
            if (is_array($issueData)) {
                $issues[] = Issue::fromArray($issueData);
            }
        }

        return new self(
            (string) ($data['name'] ?? 'unknown'),
            (string) ($data['status'] ?? 'skipped'),
            (float) ($data['duration'] ?? 0.0),
            $issues,
            isset($data['raw_output']) ? (string) $data['raw_output'] : null,
            isset($data['summary']) ? (string) $data['summary'] : null,
        );
    }
}
