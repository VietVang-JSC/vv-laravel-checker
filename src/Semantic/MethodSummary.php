<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * One summarized method return. Param-derived summaries never store a
 * concrete provenance — `return $input` is `PARAM(0)`, and only the
 * call-site (with actual arguments) decides RAW / VALIDATED / BOUNDED /
 * INTERNAL. Context-insensitive RAW would be a false resolution.
 */
final class MethodSummary
{
    public const PARAM = 'param';

    public const INTERNAL = 'internal';

    public const UNKNOWN = 'unknown';

    public const OP_PASSTHROUGH = 'passthrough';

    public const OP_ALL = 'all';

    public const OP_INPUT = 'input';

    public const OP_ONLY = 'only';

    public const OP_EXCEPT = 'except';

    public const OP_VALIDATED = 'validated';

    public const OP_SAFE = 'safe';

    /**
     * @param list<string> $params parameter names in order
     * @param list<string>|null $fields literal field-set (only/except)
     */
    public function __construct(
        public readonly string $class,
        public readonly string $method,
        public readonly string $kind,
        public readonly array $params,
        public readonly ?int $paramIndex,
        public readonly ?string $operation,
        public readonly ?array $fields,
        public readonly string $confidence,
        public readonly string $evidence,
        public readonly ?string $unresolvedReason,
    ) {
    }

    public static function unknown(string $class, string $method, string $reason): self
    {
        return new self($class, $method, self::UNKNOWN, [], null, null, null, 'low', '', $reason);
    }

    /**
     * @return array{class: string, method: string, kind: string, params: list<string>, param_index: int|null, operation: string|null, fields: list<string>|null, confidence: string, evidence: string, unresolved_reason: string|null}
     */
    public function toArray(): array
    {
        return [
            'class' => $this->class,
            'method' => $this->method,
            'kind' => $this->kind,
            'params' => $this->params,
            'param_index' => $this->paramIndex,
            'operation' => $this->operation,
            'fields' => $this->fields,
            'confidence' => $this->confidence,
            'evidence' => $this->evidence,
            'unresolved_reason' => $this->unresolvedReason,
        ];
    }
}
