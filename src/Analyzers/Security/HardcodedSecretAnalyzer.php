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

    /**
     * Values that are obviously fixtures, not leaks: whsec_test_secret,
     * AKIA...EXAMPLE (AWS's documented example), dummy/demo/sample data.
     * Only applied in test paths — production values with these markers
     * still flag (a staging sk_test_* in .env deserves a look).
     */
    private const FAKE_FIXTURE_MARKERS = [
        'test', 'fake', 'example', 'sample', 'demo', 'mock', 'dummy',
        'changeme', 'placeholder', 'xxx',
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

    /**
     * @return list<Issue>
     */
    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $issues = [];
        $lines = preg_split('/\r\n|\r|\n/', $code) ?: [];
        $isTest = $this->isTestPath($file);

        foreach ($lines as $index => $line) {
            if ($this->isFieldNameDeclaration($line)) {
                continue;
            }
            if ($this->isEnvDefaultSecret($line)) {
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Possible hardcoded secret detected: default secret in env().',
                    $file,
                    $index + 1,
                    Severity::Critical,
                    ['kind' => 'env default secret', 'hint' => mb_substr(trim($line), 0, 120)]
                );
                break;
            }
            foreach (self::PATTERNS as $pattern => $label) {
                if (preg_match($pattern, $line, $m) === 1) {
                    if ($isTest && $this->isFakeFixture($m[0])) {
                        break;
                    }
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

    private function isFakeFixture(string $matched): bool
    {
        $lower = strtolower($matched);
        foreach (self::FAKE_FIXTURE_MARKERS as $marker) {
            if (str_contains($lower, $marker)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Catches real secrets hiding as env() defaults, e.g.
     * env('PAYMENT_API_KEY', 'aB3x9...'). Skips obvious placeholders.
     */
    private function isEnvDefaultSecret(string $line): bool
    {
        if (preg_match('/\benv\(\s*[\'"]([^\'"]*(?:KEY|SECRET|PASSWORD|TOKEN|PASSWD)[^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $line, $m) !== 1) {
            return false;
        }

        $value = $m[2];
        if (preg_match('/^[A-Za-z0-9_\-]{16,}$/', $value) !== 1) {
            return false;
        }

        return preg_match('/^(xxx|changeme|password|secret|test|testing|local|dev|example|null|none|default)/i', $value) !== 1;
    }
}
