<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Checkers\CheckerInterface;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\CheckRunner;
use VietVang\QualityChecker\Runner\ResultCache;

final class CheckRunnerTest extends TestCase
{
    private function context(string $failOn): CheckContext
    {
        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            [],
            sys_get_temp_dir() . '/reports',
            failOn: $failOn,
        );
    }

    private function resultWithIssue(Severity $severity): CheckResult
    {
        $issue = new Issue('RULE_X', 'message', 'file.php', 1, $severity, 'custom');

        return new CheckResult('custom', 'failed', 0.1, [$issue], null, null);
    }

    public function testShouldFailOnErrorByDefault(): void
    {
        $runner = new CheckRunner($this->context('error'));

        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Error)]));
        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Warning)]));
        self::assertFalse($runner->shouldFail([new CheckResult('phpcs', 'passed', 0.1, [], null, null)]));
    }

    public function testShouldFailOnWarning(): void
    {
        $runner = new CheckRunner($this->context('warning'));

        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Warning)]));
    }

    public function testShouldFailOnCritical(): void
    {
        $runner = new CheckRunner($this->context('critical'));

        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Error)]));
        self::assertTrue($runner->shouldFail([$this->resultWithIssue(Severity::Critical)]));
    }

    public function testShouldNeverFailOnNone(): void
    {
        $runner = new CheckRunner($this->context('none'));

        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Critical)]));
    }

    public function testCacheDisabledBypassesGetAndPut(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-runner-' . uniqid('', true);
        $outputDir = $base . DIRECTORY_SEPARATOR . 'reports';
        @mkdir($outputDir, 0777, true);

        try {
            $ctx = new CheckContext(
                $base,
                ['app'],
                ['cache' => ['enabled' => false]],
                $outputDir,
                failOn: 'error',
            );

            $checker = new class implements CheckerInterface {
                public int $runs = 0;

                public function name(): string
                {
                    return 'stub';
                }

                public function description(): string
                {
                    return 'Stub checker';
                }

                public function isAvailable(CheckContext $ctx): bool
                {
                    return true;
                }

                public function run(CheckContext $ctx): CheckResult
                {
                    $this->runs++;

                    return new CheckResult('stub', 'passed', 0.01, [], null, 'live');
                }

                /** @return array<string, mixed> */
                public function config(): array
                {
                    return [];
                }
            };

            $cache = new ResultCache($ctx);
            $key = $cache->key($checker->name(), $ctx->paths, $checker->config());
            $stale = new CheckResult('stub', 'passed', 0.01, [], null, 'stale');
            $cache->put($key, $stale->toArray(), 3600);

            $runner = new CheckRunner($ctx);
            $results = $runner->run([$checker]);

            self::assertCount(1, $results);
            self::assertSame(1, $checker->runs);
            self::assertSame('live', $results[0]->summary);

            $cachedAfter = $cache->get($key);
            self::assertIsArray($cachedAfter);
            self::assertSame('stale', $cachedAfter['summary'] ?? null);

            $freshBase = $base . '-fresh';
            $freshOutput = $freshBase . DIRECTORY_SEPARATOR . 'reports';
            @mkdir($freshOutput, 0777, true);
            $freshCtx = new CheckContext(
                $freshBase,
                ['app'],
                ['cache' => ['enabled' => false]],
                $freshOutput,
                failOn: 'error',
            );
            (new CheckRunner($freshCtx))->run([$checker]);
            self::assertSame([], glob($freshOutput . DIRECTORY_SEPARATOR . '.cache' . DIRECTORY_SEPARATOR . '*.json') ?: []);
        } finally {
            $this->removeDir($base);
            $this->removeDir($base . '-fresh');
        }
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo) {
                $path = $file->getPathname();
                if ($file->isDir()) {
                    @rmdir($path);
                } else {
                    @unlink($path);
                }
            }
        }
        @rmdir($dir);
    }
}
