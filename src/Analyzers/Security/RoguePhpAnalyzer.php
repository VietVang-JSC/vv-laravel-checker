<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class RoguePhpAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'ROGUE_PHP';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $public = $root . DIRECTORY_SEPARATOR . 'public';
        if (!is_dir($public)) {
            return [];
        }
        $issues = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($public, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }
            $name = $file->getFilename();
            if ($name === 'index.php') {
                continue;
            }
            $issues[] = new Issue(
                self::RULE,
                sprintf('Rogue PHP file in public/: %s — only index.php should be there.', $file->getPathname()),
                $file->getPathname(),
                1,
                Severity::Critical,
                'custom',
                ['file' => $file->getFilename()],
                Confidence::High
            );
        }

        return $issues;
    }
}
