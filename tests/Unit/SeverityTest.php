<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Result\Severity;

final class SeverityTest extends TestCase
{
    public function testOrdering(): void
    {
        self::assertLessThan(
            Severity::Warning->intValue(),
            Severity::Info->intValue()
        );
        self::assertLessThan(
            Severity::Critical->intValue(),
            Severity::Error->intValue()
        );
        self::assertGreaterThan(
            Severity::Info->intValue(),
            Severity::Critical->intValue()
        );
    }

    public function testFromString(): void
    {
        self::assertSame(Severity::Critical, Severity::fromString('critical'));
        self::assertSame(Severity::Error, Severity::fromString('HIGH'));
        self::assertSame(Severity::Error, Severity::fromString('unknown'));
    }

    public function testBackedValues(): void
    {
        self::assertSame('info', Severity::Info->value);
        self::assertSame('warning', Severity::Warning->value);
        self::assertSame('error', Severity::Error->value);
        self::assertSame('critical', Severity::Critical->value);
    }
}
