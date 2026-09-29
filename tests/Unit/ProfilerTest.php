<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Profiling\Profiler;

/**
 * PERF-EVAL-1: profiler is OFF by default, measures without influencing,
 * and emits a stable machine-readable shape.
 */
final class ProfilerTest extends TestCase
{
    protected function tearDown(): void
    {
        Profiler::reset();
        Profiler::setEnabled(false);
    }

    public function testDisabledByDefault(): void
    {
        self::assertFalse(Profiler::isEnabled());
        Profiler::countParse();
        Profiler::countRead('x.php');
        Profiler::begin('s');
        Profiler::end('s');

        self::assertSame([], Profiler::report()['timers_ms']);
        self::assertSame([], Profiler::report()['counters']);
    }

    public function testCollectsWhenEnabled(): void
    {
        Profiler::setEnabled(true);
        Profiler::countParse('a.php');
        Profiler::countParse('a.php');
        Profiler::countParse();
        Profiler::countRead('a.php');
        Profiler::countRead('b.php');
        Profiler::countFilesVisited('XAnalyzer', 10);
        Profiler::begin('discovery');
        Profiler::end('discovery');
        $timed = Profiler::timeAnalyzer('XAnalyzer', static fn (): string => 'ok');

        self::assertSame('ok', $timed);
        $report = Profiler::report();
        self::assertSame(3, $report['counters']['parse_operations']);
        self::assertSame(2, $report['counters']['file_reads']);
        self::assertSame(10, $report['counters']['file_visits']);
        self::assertSame(2, $report['unique_files_read']);
        self::assertSame(1, $report['unique_files_parsed']);
        self::assertArrayHasKey('discovery', $report['timers_ms']);
        self::assertArrayHasKey('analyzer:XAnalyzer', $report['timers_ms']);
    }

    public function testEnvEnables(): void
    {
        putenv('QUALITY_CHECKER_PROFILE=1');
        try {
            Profiler::enableFromEnvironment();
            self::assertTrue(Profiler::isEnabled());
        } finally {
            putenv('QUALITY_CHECKER_PROFILE');
            Profiler::setEnabled(false);
        }
    }
}
