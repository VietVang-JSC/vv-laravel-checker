<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * Composable authorization evidence from a middleware `handle()`.
 * Answers "why is this finding absent?" — and, when attached to a
 * review finding's `middleware_resolution`, "what did the engine see?".
 */
final class MiddlewareEvidence
{
    public const MECHANISM_GATE = 'gate';

    public const MECHANISM_ROLE = 'role';

    public function __construct(
        public readonly string $type,
        public readonly string $alias,
        public readonly string $class,
        public readonly string $method,
        public readonly string $mechanism,
        public readonly ?string $ability,
        public readonly string $source,
        public readonly string $confidence,
    ) {
    }

    /**
     * @return array{type: string, alias: string, class: string, method: string, mechanism: string, ability: string|null, source: string, confidence: string}
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'alias' => $this->alias,
            'class' => $this->class,
            'method' => $this->method,
            'mechanism' => $this->mechanism,
            'ability' => $this->ability,
            'source' => $this->source,
            'confidence' => $this->confidence,
        ];
    }
}
