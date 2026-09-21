<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class HardcodedSecretAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'HARDCODED_SECRET';

    private const PATTERNS = [
        '/sk-(?:[A-Za-z0-9]){20,}/' => 'OpenAI API key',
        '/AKIA[0-9A-Z]{16}/' => 'AWS access key',
        '/AIza[0-9A-Za-z_-]{35}/' => 'Google API key',
        '/ghp_[0-9A-Za-z]{36}/' => 'GitHub token',
        '/github_pat_[0-9A-Za-z_]{22,}/' => 'GitHub PAT',
        '/xox[baprs]-[0-9A-Za-z-]{10,}/' => 'Slack token',
        '/pk_live_[0-9A-Za-z]{16,}/' => 'Stripe publishable key',
        '/sk_live_[0-9A-Za-z]{16,}/' => 'Stripe secret key',
        '/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/' => 'private key block',
        '/AIzaSy[0-9A-Za-z_-]{33}/' => 'Google API key',
        '/(?i)api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']/' => 'generic API key assignment',
        '/(?i)secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']/' => 'generic secret assignment',
        '/(?i)password["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']/' => 'hardcoded password',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $issues = [];
        $lines = preg_split('/\r\n|\r|\n/', $code) ?: [];

        foreach ($lines as $index => $line) {
            foreach (self::PATTERNS as $pattern => $label) {
                if (preg_match($pattern, $line, $m) === 1) {
                    $issues[] = $this->makeIssue(
                        self::RULE,
                        sprintf('Possible hardcoded secret detected: %s.', $label),
                        $file,
                        $index + 1,
                        Severity::Critical,
                        ['kind' => $label, 'hint' => mb_substr(trim($line), 0, 120)]
                    );
                    break;
                }
            }
        }

        return $issues;
    }
}
