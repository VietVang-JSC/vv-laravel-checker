<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Checkers\CheckerInterface;
use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Runner\CheckRunner;
use Rampart\QualityChecker\Runner\ResultCache;

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

    public function testIgnoredRulesAreDroppedFromResults(): void
    {
        $ctx = new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            ['quality_gate' => ['ignore' => ['MISSING_MODEL_TEST']]],
            sys_get_temp_dir() . '/reports',
            failOn: 'error',
        );
        $ignored = new Issue('MISSING_MODEL_TEST', 'message', 'file.php', 1, Severity::Warning, 'custom');
        $kept = new Issue('OWASP_SSRF', 'message', 'file.php', 2, Severity::Error, 'custom');
        $checker = new class ([$ignored, $kept]) implements CheckerInterface {
            /** @var Issue[] */
            private array $issues;

            /** @param Issue[] $issues */
            public function __construct(array $issues)
            {
                $this->issues = $issues;
            }

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
                return new CheckResult('stub', 'failed', 0.01, $this->issues, null, null);
            }

            /** @return array<string, mixed> */
            public function config(): array
            {
                return [];
            }
        };

        $results = (new CheckRunner($ctx))->run([$checker]);

        self::assertCount(1, $results);
        self::assertCount(1, $results[0]->issues);
        self::assertSame('OWASP_SSRF', $results[0]->issues[0]->rule);
    }

    public function testEmptyIgnoreListKeepsEverything(): void
    {
        $runner = new CheckRunner($this->context('error'));

        $results = $runner->run([new class implements CheckerInterface {
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
                return new CheckResult('stub', 'failed', 0.01, [], null, null);
            }

            /** @return array<string, mixed> */
            public function config(): array
            {
                return [];
            }
        }]);

        self::assertCount(1, $results);
    }

    /**
     * The cache-hit branch — the one that decides whether a checker runs at all.
     *
     * This is the highest-consequence branch in the runner and it had no test:
     * every other test in this file passes `noCache: true` or a config with
     * `cache.enabled => false`, so a regression that served results from cache
     * instead of running the checker — the failure mode being a gate that reports
     * last run's findings forever — would not have failed a single test.
     *
     * The stub counts its invocations, so "was it re-run?" is asserted directly
     * rather than inferred from the summary text.
     */
    public function testWarmCacheServesTheStoredResultWithoutRunningTheCheckerAgain(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-cache-hit-' . bin2hex(random_bytes(6));
        $outputDir = $base . DIRECTORY_SEPARATOR . 'reports';
        mkdir($outputDir, 0777, true);

        try {
            $ctx = new CheckContext($base, ['app'], [], $outputDir, failOn: 'error');

            $checker = new class implements CheckerInterface {
                public int $runs = 0;
                public string $summary = 'first-run';

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

                    return new CheckResult('stub', 'passed', 0.01, [], null, $this->summary);
                }

                /** @return array<string, mixed> */
                public function config(): array
                {
                    return [];
                }
            };

            $runner = new CheckRunner($ctx);

            $first = $runner->run([$checker]);
            self::assertSame(1, $checker->runs);
            self::assertSame('first-run', $first[0]->summary);

            // Change what a live run would report, then run again. The cached
            // result must win, which is the whole point of the cache.
            $checker->summary = 'second-run';
            $second = (new CheckRunner($ctx))->run([$checker]);

            self::assertSame(1, $checker->runs, 'the checker must not run again on a cache hit');
            self::assertSame('first-run', $second[0]->summary, 'the cached result must be served');

            // --no-cache on the same context must bypass it in the other direction.
            $bypass = new CheckContext($base, ['app'], [], $outputDir, noCache: true, failOn: 'error');
            $third = (new CheckRunner($bypass))->run([$checker]);

            self::assertSame(2, $checker->runs);
            self::assertSame('second-run', $third[0]->summary);
        } finally {
            $this->removeDir($base);
        }
    }

    /**
     * A cache entry written by one version of the checker code must not be
     * served after the code changes: the key embeds `ResultCache::codeVersion()`,
     * so a modified analyzer produces a different key and therefore a miss.
     */
    public function testExpiredCacheEntryIsNotServed(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-cache-expiry-' . bin2hex(random_bytes(6));
        $outputDir = $base . DIRECTORY_SEPARATOR . 'reports';
        mkdir($outputDir, 0777, true);

        try {
            $ctx = new CheckContext($base, ['app'], [], $outputDir, failOn: 'error');
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

            $runner = new CheckRunner($ctx);
            $runner->run([$checker]);
            self::assertSame(1, $checker->runs);

            // Expire every entry behind the runner's back.
            $cacheDir = $outputDir . DIRECTORY_SEPARATOR . '.cache';
            foreach ((array) glob($cacheDir . DIRECTORY_SEPARATOR . '*.json') as $file) {
                $payload = json_decode((string) file_get_contents((string) $file), true);
                $payload['expires_at'] = time() - 1;
                file_put_contents((string) $file, (string) json_encode($payload));
            }

            $results = (new CheckRunner($ctx))->run([$checker]);

            self::assertSame(2, $checker->runs, 'an expired entry must be re-run, not served');
            self::assertSame('live', $results[0]->summary);
        } finally {
            $this->removeDir($base);
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
