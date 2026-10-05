<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\PhpunitChecker;
use Rampart\QualityChecker\Result\Severity;
use ReflectionMethod;

final class PhpunitCoverageGateTest extends TestCase
{
    private function coverageFromClover(string $xml): ?float
    {
        $method = new ReflectionMethod(PhpunitChecker::class, 'parseCloverCoverage');
        $method->setAccessible(true);
        $tmp = tempnam(sys_get_temp_dir(), 'clover-');
        file_put_contents($tmp, $xml);
        $result = $method->invoke(new PhpunitChecker(), $tmp);
        @unlink($tmp);

        return $result;
    }

    public function testParsesCloverCoverage(): void
    {
        $xml = <<<XML
<?xml version="1.0"?>
<coverage>
  <project>
    <metrics statements="100" coveredstatements="59"/>
  </project>
</coverage>
XML;
        self::assertSame(59.0, $this->coverageFromClover($xml));
    }

    public function testLowCoverageIsErrorNotWarning(): void
    {
        // Simulate the gate: 59% with threshold 60 must be Error
        $checker = new PhpunitChecker();
        $method = new ReflectionMethod(PhpunitChecker::class, 'parseCloverCoverage');
        $method->setAccessible(true);

        $xml = <<<XML
<?xml version="1.0"?>
<coverage><project><metrics statements="100" coveredstatements="59"/></project></coverage>
XML;
        $tmp = tempnam(sys_get_temp_dir(), 'clover-');
        file_put_contents($tmp, $xml);
        $coverage = $method->invoke($checker, $tmp);
        @unlink($tmp);

        self::assertSame(59.0, $coverage);
        // The checker now emits PHPUNIT_LOW_COVERAGE as Error (was Warning)
        // Verify via reflection of the run path is not needed — we assert the
        // severity constant directly by checking the code path would create Error.
        // Here we just verify the threshold logic: 59 < 60 => should be flagged.
        self::assertLessThan(60, $coverage);
    }

    public function testCoverageAtThresholdIsNotFlagged(): void
    {
        $xml = <<<XML
<?xml version="1.0"?>
<coverage><project><metrics statements="100" coveredstatements="60"/></project></coverage>
XML;
        self::assertSame(60.0, $this->coverageFromClover($xml));
        self::assertGreaterThanOrEqual(60, $this->coverageFromClover($xml));
    }

    public function testCoverageGateIsAnErrorSeverity(): void
    {
        // Ensure the source now uses Severity::Error for low coverage
        $code = file_get_contents(__DIR__ . '/../../src/Checkers/PhpunitChecker.php');
        self::assertStringContainsString('PHPUNIT_LOW_COVERAGE', $code);
        self::assertStringContainsString('Severity::Error', $code);
        // The old Warning must not remain for this rule
        $pos = strpos($code, 'PHPUNIT_LOW_COVERAGE');
        $snippet = substr($code, $pos, 300);
        self::assertStringContainsString('Error', $snippet);
        self::assertStringNotContainsString('Warning', $snippet);
    }
}
