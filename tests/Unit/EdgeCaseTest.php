<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Runner\CheckRunner;

final class EdgeCaseTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-edge-' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
    }

    public function testEmptyProjectDoesNotCrash(): void
    {
        $ctx = new CheckContext(
            $this->tempDir,
            [],
            ['auto_install_tools' => false],
            $this->tempDir . '/reports',
            noCache: true,
            only: ['custom'],
        );

        $runner = new CheckRunner($ctx);
        $checkers = $runner->buildCheckers();
        $results = $runner->run($checkers);

        self::assertIsArray($results);
        self::assertCount(1, $results);
        self::assertSame('custom', $results[0]->name);
    }

    public function testNonExistentPathRunsGracefully(): void
    {
        $ctx = new CheckContext(
            $this->tempDir,
            ['does-not-exist'],
            ['auto_install_tools' => false],
            $this->tempDir . '/reports',
            noCache: true,
            only: ['custom'],
        );

        $runner = new CheckRunner($ctx);
        $results = $runner->run($runner->buildCheckers());

        self::assertIsArray($results);
        self::assertCount(1, $results);
        self::assertInstanceOf(CheckResult::class, $results[0]);
    }

    public function testShouldFailNeverTrueForFailOnNone(): void
    {
        $runner = new CheckRunner(new CheckContext($this->tempDir, ['app'], [], $this->tempDir . '/reports', failOn: 'none'));

        self::assertFalse($runner->shouldFail([$this->resultWithIssue(Severity::Critical)]));
        self::assertFalse($runner->shouldFail([]));
    }

    public function testShouldFailFalseForEmptyResults(): void
    {
        $runner = new CheckRunner(new CheckContext($this->tempDir, ['app'], [], $this->tempDir . '/reports', failOn: 'error'));

        self::assertFalse($runner->shouldFail([]));
    }

    public function testSeverityFromStringDefaultsOnGarbage(): void
    {
        self::assertSame(Severity::Error, Severity::fromString('garbage'));
        self::assertSame(Severity::Error, Severity::fromString(''));
    }

    public function testConfidenceFromStringDefaultsOnGarbage(): void
    {
        self::assertSame(Confidence::Low, Confidence::fromString('garbage'));
        self::assertSame(Confidence::Low, Confidence::fromString(''));
    }

    public function testResolvePathHandlesAbsoluteWindowsPath(): void
    {
        $ctx = new CheckContext($this->tempDir, ['app'], [], $this->tempDir . '/reports');

        self::assertSame('C:\\foo', $ctx->resolvePath('C:\\foo'));
        self::assertSame('C:/foo', $ctx->resolvePath('C:/foo'));
    }

    public function testResolvePathHandlesRelativeTraversal(): void
    {
        $ctx = new CheckContext($this->tempDir, ['app'], [], $this->tempDir . '/reports');

        self::assertSame(
            rtrim($this->tempDir, '/\\') . DIRECTORY_SEPARATOR . '../relative',
            $ctx->resolvePath('../relative')
        );
    }

    public function testIssueFromArrayMissingKeysUsesDefaults(): void
    {
        $issue = Issue::fromArray([]);

        self::assertSame('UNKNOWN', $issue->rule);
        self::assertSame('', $issue->message);
        self::assertNull($issue->file);
        self::assertNull($issue->line);
        self::assertSame(Severity::Error, $issue->severity);
        self::assertSame('custom', $issue->source);
        self::assertSame([], $issue->metadata);
        self::assertSame(Confidence::High, $issue->confidence);
    }

    private function resultWithIssue(Severity $severity): CheckResult
    {
        return new CheckResult(
            'custom',
            'failed',
            0.1,
            [new Issue('RULE_X', 'message', 'file.php', 1, $severity, 'custom')],
            null,
            null
        );
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

        foreach ($iterator as $item) {
            if ($item instanceof \SplFileInfo) {
                if ($item->isDir()) {
                    @rmdir($item->getPathname());
                } else {
                    @unlink($item->getPathname());
                }
            }
        }

        @rmdir($dir);
    }
}
