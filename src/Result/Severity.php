<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Result;

enum Severity: string
{
    case Info = 'info';
    case Warning = 'warning';
    case Error = 'error';
    case Critical = 'critical';

    public function intValue(): int
    {
        return match ($this) {
            self::Info => 1,
            self::Warning => 2,
            self::Error => 3,
            self::Critical => 4,
        };
    }

    public static function fromString(string $value): self
    {
        return self::tryFrom(strtolower($value)) ?? self::Error;
    }
}
