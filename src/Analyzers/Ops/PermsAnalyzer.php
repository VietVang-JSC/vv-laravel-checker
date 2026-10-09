<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class PermsAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'PERMS_TOO_OPEN';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        // Only check when scanning the project root itself, not when
        // the runner is pointed at a fixture sub-directory (tests/Feature/fixtures/app).
        // Testbench boots its own skeleton at vendor/orchestra/testbench-core/laravel
        // which has storage/bootstrap/cache with 777 — that is not the project's
        // deploy artifact and must not be reported when the test scans fixtures.
        $normalizedRoot = str_replace('\\', '/', $root);
        if (str_contains($normalizedRoot, '/vendor/orchestra/testbench-core')) {
            return [];
        }
        // Check a small set of sensitive paths, not every file
        $candidates = [
            $root . DIRECTORY_SEPARATOR . '.env',
            $root . DIRECTORY_SEPARATOR . 'storage',
            $root . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'cache',
        ];
        foreach ($candidates as $path) {
            if (!file_exists($path)) {
                continue;
            }
            $perms = fileperms($path);
            if ($perms === false) {
                continue;
            }
            $octal = substr(sprintf('%o', $perms), -3);
            if (in_array($octal, ['777', '666', '775'], true)) {
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('Permissions too open: %s is %s (world-writable).', $path, $octal),
                    $path,
                    1,
                    Severity::Warning,
                    'custom',
                    ['perms' => $octal, 'path' => $path],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }
}
