<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Result;

final class Issue
{
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
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['rule'] ?? 'UNKNOWN'),
            (string) ($data['message'] ?? ''),
            isset($data['file']) && $data['file'] !== null ? (string) $data['file'] : null,
            isset($data['line']) && $data['line'] !== null ? (int) $data['line'] : null,
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
