<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

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

    /**
     * Well-known secret prefixes used to tag evidence without ever storing
     * the full secret value.
     *
     * @var list<string>
     */
    private const KNOWN_SECRET_PREFIXES = [
        'sk_live_',
        'sk_test_',
        'ghp_',
        'github_pat_',
        'AKIA',
        'AIza',
        'xoxb-',
        'xoxp-',
        'xoxa-',
        'xoxr-',
        'xoxs-',
        'pk_live_',
        'whsec_',
        '-----BEGIN',
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
            $envSecret = $this->envDefaultSecret($line);
            if ($envSecret !== null) {
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Possible hardcoded secret detected: default secret in env().',
                    $file,
                    $index + 1,
                    Severity::Critical,
                    [
                        'kind' => 'env default secret',
                        'hint' => mb_substr(trim($line), 0, 120),
                        'evidence' => $this->buildEvidence($envSecret),
                    ]
                );
                break;
            }
            foreach (self::PATTERNS as $pattern => $label) {
                if (preg_match($pattern, $line, $m) === 1) {
                    if ($this->isIdentifierConstant($line, $m[0])) {
                        break;
                    }
                    if ($isTest && $this->isFakeFixture($m[0])) {
                        break;
                    }
                    $issues[] = $this->makeIssue(
                        self::RULE,
                        sprintf('Possible hardcoded secret detected: %s.', $label),
                        $file,
                        $index + 1,
                        Severity::Critical,
                        [
                            'kind' => $label,
                            'hint' => mb_substr(trim($line), 0, 120),
                            'evidence' => $this->buildEvidence($m[0]),
                        ]
                    );
                    break;
                }
            }
            $comparison = $this->hardcodedPasswordComparison($line);
            if ($comparison !== null) {
                if ($this->isIdentifierConstant($line, $comparison)) {
                    continue;
                }
                if ($isTest && $this->isFakeFixture($comparison)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Possible hardcoded secret detected: password compared against a hardcoded literal (master-password/backdoor pattern).',
                    $file,
                    $index + 1,
                    Severity::Critical,
                    [
                        'kind' => 'hardcoded password comparison',
                        'hint' => mb_substr(trim($line), 0, 120),
                        'evidence' => $this->buildEvidence($comparison),
                    ]
                );
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
     * Master-password pattern: a password-ish value compared (==/===/!=/!==)
     * against a long string literal, e.g. if ($credentials['password'] ==
     * '!S3cret...'). Returns the literal for fixture screening, null when
     * the line does not match.
     */
    private function hardcodedPasswordComparison(string $line): ?string
    {
        $patterns = [
            "/(?i)\\b(?:password|passwd|pwd)\\b['\"\\]\\s]*?(?:==|===|!=|!==)\\s*['\"]([^'\"]{8,})['\"]/",
            "/(?i)['\"]([^'\"]{8,})['\"]\\s*(?:==|===|!=|!==)\\s*.*?\\b(?:password|passwd|pwd)\\b/",
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line, $m) === 1) {
                return $m[1];
            }
        }

        return null;
    }

    /**
     * Catches real secrets hiding as env() defaults, e.g.
     * env('PAYMENT_API_KEY', 'aB3x9...'). Skips obvious placeholders.
     * Returns the default value when it looks like a real secret, null
     * otherwise.
     */
    private function envDefaultSecret(string $line): ?string
    {
        if (preg_match('/\benv\(\s*[\'"]([^\'"]*(?:KEY|SECRET|PASSWORD|TOKEN|PASSWD)[^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $line, $m) !== 1) {
            return null;
        }

        $value = (string) $m[2];
        if (preg_match('/^[A-Za-z0-9_\-]{16,}$/', $value) !== 1) {
            return null;
        }

        if (preg_match('/^(xxx|changeme|password|secret|test|testing|local|dev|example|null|none|default)/i', $value) === 1) {
            return null;
        }

        return $value;
    }

    /**
     * Identifier constants name a field or option key rather than holding a
     * credential, e.g. `const FEATURE_CLIENT_PORTAL_PASSWORD =
     * 'client_portal_password'`. When the line declares an UPPER_SNAKE class
     * constant (or define()) and the matched secret text is name-like — its
     * normalized form is a substring of (or contains) the normalized const
     * name — the match is skipped.
     */
    private function isIdentifierConstant(string $line, string $matched): bool
    {
        if (preg_match('/(?:const\s+([A-Z][A-Z0-9_]*)|define\s*\(\s*[\'"]([A-Z][A-Z0-9_]*)[\'"])/', $line, $constant) !== 1) {
            return false;
        }

        $name = $constant[1] !== '' ? (string) $constant[1] : (string) $constant[2];
        $normalizedName = $this->normalizeIdentifier($name);
        if ($normalizedName === '') {
            return false;
        }

        $values = [$matched];
        if (preg_match_all('/[\'"]([^\'"]+)[\'"]/', $matched, $quoted) > 0) {
            $values = $quoted[1];
        }

        foreach ($values as $value) {
            $normalizedValue = $this->normalizeIdentifier((string) $value);
            if ($normalizedValue === '') {
                continue;
            }
            if (str_contains($normalizedName, $normalizedValue) || str_contains($normalizedValue, $normalizedName)) {
                return true;
            }
        }

        return false;
    }

    private function normalizeIdentifier(string $value): string
    {
        $stripped = preg_replace('/[^a-z0-9]/', '', strtolower($value));

        return is_string($stripped) ? $stripped : '';
    }

    /**
     * Short, non-sensitive evidence about a matched secret: a truncated
     * preview plus length, Shannon entropy, well-known prefix and fixture
     * flag. The full secret value is never stored.
     *
     * @return array{matched: string, length: int, entropy: float, known_prefix: ?string, test_fixture: bool}
     */
    private function buildEvidence(string $matched): array
    {
        return [
            'matched' => mb_substr($matched, 0, 32),
            'length' => strlen($matched),
            'entropy' => $this->shannonEntropy($matched),
            'known_prefix' => $this->knownPrefix($matched),
            'test_fixture' => $this->isFakeFixture($matched),
        ];
    }

    private function shannonEntropy(string $value): float
    {
        $length = strlen($value);
        if ($length === 0) {
            return 0.0;
        }

        $frequencies = array_count_values(str_split($value));
        $entropy = 0.0;
        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return round($entropy, 2);
    }

    private function knownPrefix(string $matched): ?string
    {
        foreach (self::KNOWN_SECRET_PREFIXES as $prefix) {
            if (str_contains($matched, $prefix)) {
                return $prefix;
            }
        }

        return null;
    }
}
