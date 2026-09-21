<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Result;

enum Confidence: string
{
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';

    public function intValue(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
        };
    }

    public static function fromString(string $value): self
    {
        return self::tryFrom(strtolower($value)) ?? self::Low;
    }
}
