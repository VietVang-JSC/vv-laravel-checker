<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * One classified input-to-sink flow. The status describes provenance,
 * never a verdict: `validated` does NOT mean mass-assignment safe (a
 * validated `is_admin` field is still a mass-assignment issue) — field
 * reasoning lands in v0.4.2 with model metadata.
 */
final class MassFlow
{
    public const RAW = 'tainted-raw';

    public const VALIDATED = 'validated';

    public const BOUNDED = 'bounded';

    public const INTERNAL = 'internal';

    public const UNKNOWN = 'unknown';

    /**
     * @param list<string>|null $fields bounded/known fields (only())
     * @param list<string>|null $excluded removed fields (except())
     * @param list<array{kind: string, detail: string, line: int|null}> $trace
     */
    public function __construct(
        public readonly string $status,
        public readonly ?array $fields,
        public readonly ?array $excluded,
        public readonly bool $forceBypass,
        public readonly string $source,
        public readonly string $sink,
        public readonly array $trace,
    ) {
    }

    /**
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, force_bypass: bool, source: string, sink: string, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'fields' => $this->fields,
            'excluded' => $this->excluded,
            'force_bypass' => $this->forceBypass,
            'source' => $this->source,
            'sink' => $this->sink,
            'trace' => $this->trace,
        ];
    }
}
