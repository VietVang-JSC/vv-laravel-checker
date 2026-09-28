<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * Authorization evidence from a FormRequest `authorize()` method.
 * `return true` (and absent `authorize()`) yield MECH_NONE — explicitly
 * not protection. Ability checks yield MECH_CAN; anything else
 * non-trivial yields MECH_CUSTOM (unrecognized but real logic, kept as
 * protection by consumers for backward compatibility).
 */
final class AuthorizationEvidence
{
    public const SOURCE_FORM_REQUEST = 'form-request';

    public const MECH_CAN = 'authorize-can';

    public const MECH_CUSTOM = 'authorize-custom';

    public const MECH_DENY = 'authorize-deny';

    public const MECH_NONE = 'authorize-none';

    public function __construct(
        public readonly string $source,
        public readonly string $requestClass,
        public readonly string $mechanism,
        public readonly ?string $ability,
        public readonly string $confidence,
    ) {
    }

    /**
     * @return array{source: string, request_class: string, mechanism: string, ability: string|null, confidence: string}
     */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'request_class' => $this->requestClass,
            'mechanism' => $this->mechanism,
            'ability' => $this->ability,
            'confidence' => $this->confidence,
        ];
    }
}
