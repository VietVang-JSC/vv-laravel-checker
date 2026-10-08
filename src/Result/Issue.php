<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Result;

final class Issue
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $rule,
        public string $message,
        public ?string $file,
        public ?int $line,
        public Severity $severity,
        public string $source,
        public array $metadata = [],
        public Confidence $confidence = Confidence::High,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
            'severity' => $this->severity->value,
            'source' => $this->source,
            'metadata' => $this->metadata,
            'confidence' => $this->confidence->value,
            'confidence_score' => $this->confidenceScore(),
        ];
    }

    /**
     * Numeric confidence 0.0-1.0. Same weights as the quality-score
     * deductions (see Reporters\QualityScore) so reports stay consistent.
     */
    public function confidenceScore(): float
    {
        return match ($this->confidence) {
            Confidence::High => 1.0,
            Confidence::Medium => 0.5,
            Confidence::Low => 0.25,
        };
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['rule'] ?? 'UNKNOWN'),
            (string) ($data['message'] ?? ''),
            isset($data['file']) ? (string) $data['file'] : null,
            isset($data['line']) ? (int) $data['line'] : null,
            Severity::fromString((string) ($data['severity'] ?? 'error')),
            (string) ($data['source'] ?? 'custom'),
            is_array($data['metadata'] ?? null) ? $data['metadata'] : [],
            Confidence::fromString((string) ($data['confidence'] ?? 'high')),
        );
    }

    /**
     * Signature used for baseline files and deduplication.
     */
    public function signature(): string
    {
        return md5(implode('|', [
            $this->rule,
            (string) $this->file,
            (string) ($this->line ?? 0),
            $this->message,
        ]));
    }
}
