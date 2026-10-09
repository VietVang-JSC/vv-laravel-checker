<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class ObfuscatedAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'OBFUSCATED_PHP';

    private const PATTERNS = [
        '/eval\s*\(\s*base64_decode\s*\(/i' => 'eval(base64_decode(...))',
        '/gzinflate\s*\(\s*base64_decode\s*\(/i' => 'gzinflate(base64_decode(...))',
        '/str_rot13\s*\(/i' => 'str_rot13(...)',
        '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(/i' => 'chr() concatenation',
        '/\\\\x[0-9a-f]{2}/i' => 'hex-encoded string',
    ];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $code = $this->sharedSource($file);
            if ($code === '') {
                continue;
            }
            foreach (self::PATTERNS as $pattern => $label) {
                if (preg_match($pattern, $code) === 1) {
                    $issues[] = new Issue(
                        self::RULE,
                        sprintf('Obfuscated PHP detected: %s.', $label),
                        $file,
                        1,
                        Severity::Critical,
                        'custom',
                        ['pattern' => $pattern],
                        Confidence::Medium
                    );
                    break;
                }
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }
}
