<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Baseline\BaselineFilter;
use VietVang\QualityChecker\Baseline\BaselineManager;
use VietVang\QualityChecker\Result\CheckResult;

final class BaselineTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'quality-checker-baseline-' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
    }

    private function baselineFile(): string
    {
        return $this->tempDir . DIRECTORY_SEPARATOR . 'baseline.json';
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function issueArray(array $overrides = []): array
    {
        return array_merge([
            'rule' => 'RULE_X',
            'message' => 'some message',
            'file' => '/app/File.php',
            'line' => 10,
            'severity' => 'error',
            'source' => 'custom',
            'metadata' => [],
            'confidence' => 'high',
        ], $overrides);
    }

    public function testLoadMissingFileReturnsEmpty(): void
    {
        $manager = new BaselineManager($this->baselineFile());

        self::assertSame([], $manager->load());
    }

    public function testUpdateWritesBaselineArrayAndLoadRoundTrips(): void
    {
        $manager = new BaselineManager($this->baselineFile());
        $results = [['issues' => [$this->issueArray()]]];

        $manager->update($results, $this->baselineFile());

        self::assertFileExists($this->baselineFile());

        $decoded = json_decode((string) file_get_contents($this->baselineFile()), true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('baseline', $decoded);
        self::assertIsArray($decoded['baseline']);
        self::assertNotEmpty($decoded['baseline']);

        $fresh = new BaselineManager($this->baselineFile());
        $loaded = $fresh->load();

        self::assertSame($decoded['baseline'], array_values($loaded));
    }

    public function testIsBaselinedMatchesSignatureOnly(): void
    {
        $manager = new BaselineManager();
        $manager->load();

        $issue = $this->issueArray();

        self::assertFalse($manager->isBaselined($issue));

        $manager->update([['issues' => [$issue]]], $this->baselineFile());

        self::assertTrue($manager->isBaselined($issue));
        self::assertFalse($manager->isBaselined($this->issueArray(['message' => 'different message'])));
    }

    public function testGenerateBaselineDeduplicates(): void
    {
        $manager = new BaselineManager();
        $issue = $this->issueArray();

        $sigs = $manager->generateBaseline([
            ['issues' => [$issue, $issue]],
            ['issues' => [$issue]],
        ]);

        self::assertCount(1, $sigs);
        self::assertSame($manager->signature($issue), array_key_first($sigs));
    }

    public function testFilterPlainArraysSetsPassedWhenAllBaselined(): void
    {
        $manager = new BaselineManager();
        $manager->update([['issues' => [$this->issueArray()]]], $this->baselineFile());

        $filter = new BaselineFilter($manager);

        $results = [
            [
                'name' => 'custom',
                'status' => 'failed',
                'duration' => 0.1,
                'issues' => [$this->issueArray()],
                'raw_output' => null,
                'summary' => null,
            ],
        ];

        $filtered = $filter->filter($results);

        self::assertSame('passed', $filtered[0]['status']);
        self::assertSame([], $filtered[0]['issues']);
        self::assertSame(1, $filter->countBaselined());
    }

    public function testFilterPlainArraysKeepsNonBaselinedIssues(): void
    {
        $manager = new BaselineManager();
        $manager->update([['issues' => [$this->issueArray()]]], $this->baselineFile());

        $filter = new BaselineFilter($manager);

        $newIssue = $this->issueArray(['rule' => 'RULE_NEW']);
        $results = [
            [
                'name' => 'custom',
                'status' => 'failed',
                'duration' => 0.1,
                'issues' => [$this->issueArray(), $newIssue],
                'raw_output' => null,
                'summary' => null,
            ],
        ];

        $filtered = $filter->filter($results);

        self::assertSame('failed', $filtered[0]['status']);
        self::assertCount(1, $filtered[0]['issues']);
        self::assertSame('RULE_NEW', $filtered[0]['issues'][0]['rule']);
        self::assertSame(1, $filter->countBaselined());
    }

    public function testFilterCheckResultObjects(): void
    {
        $manager = new BaselineManager();
        $issue = $this->issueArray();
        $manager->update([['issues' => [$issue]]], $this->baselineFile());

        $filter = new BaselineFilter($manager);

        // BaselineFilter accepts plain-array issues inside an object-shaped
        // result; the Issue[] document-level contract is intentionally violated
        // to exercise the object branch with array-shaped issues.
        $checkResult = new CheckResult(
            'custom',
            'failed',
            0.1,
            [$issue], // @phpstan-ignore-line array issues are a supported input shape
            null,
            null
        );

        $filtered = $filter->filter([$checkResult]);

        self::assertSame('passed', $filtered[0]->status);
        self::assertSame([], $filtered[0]->issues);
        self::assertSame(1, $filter->countBaselined());
    }

    public function testCountBaselinedResetsBetweenCalls(): void
    {
        $manager = new BaselineManager();
        $manager->update([['issues' => [$this->issueArray()]]], $this->baselineFile());

        $filter = new BaselineFilter($manager);
        $result = [['name' => 'custom', 'status' => 'failed', 'duration' => 0.1, 'issues' => [$this->issueArray()], 'raw_output' => null, 'summary' => null]];

        $filter->filter($result);
        self::assertSame(1, $filter->countBaselined());

        $filter->filter([['name' => 'custom', 'status' => 'passed', 'duration' => 0.1, 'issues' => [], 'raw_output' => null, 'summary' => null]]);
        self::assertSame(0, $filter->countBaselined());
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
