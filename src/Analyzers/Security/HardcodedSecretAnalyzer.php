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

    /**
     * Identifier fragments marking a field/option NAME rather than a secret
     * value (e.g. `const OPT_DB_PASSWORD = 'db-password'` — the right side
     * names the CLI option, it is not a credential).
     */
    private const FIELD_NAME_MARKERS = [
        'OPT', 'OPTION', 'FLAG', 'COLUMN', 'FIELD', 'LABEL', 'ATTR', 'PARAM',
    ];

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
            if ($this->isFieldNameDeclaration($line)) {
                continue;
            }
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

    private function isFieldNameDeclaration(string $line): bool
    {
        foreach (self::FIELD_NAME_MARKERS as $marker) {
            if (preg_match('/\b' . $marker . '(_|$)/i', $line) === 1) {
                return true;
            }
        }

        return false;
    }
}
