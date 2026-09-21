<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Checkers\PhpunitChecker;

final class CoverageParseTest extends TestCase
{
    private function clover(float $statements, float $covered): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<coverage><project>'
            . '<metrics statements="' . $statements . '" coveredstatements="' . $covered . '" />'
            . '</project></coverage>';
    }

    private function parseCoverage(string $xml): ?float
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'clover-' . uniqid('', true) . '.xml';
        file_put_contents($path, $xml);

        try {
            $checker = new PhpunitChecker();
            $ref = new \ReflectionMethod($checker, 'parseCloverCoverage');
            $ref->setAccessible(true);

            return $ref->invoke($checker, $path);
        } finally {
            @unlink($path);
        }
    }

    public function testParseCoverage(): void
    {
        self::assertSame(75.0, $this->parseCoverage($this->clover(100, 75)));
    }

    public function testParseCoverageZeroElementsReturnsNull(): void
    {
        self::assertNull($this->parseCoverage($this->clover(0, 0)));
    }

    public function testParseCoverageInvalidXmlReturnsNull(): void
    {
        self::assertNull($this->parseCoverage('not xml'));
    }
}
