<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A05 Security Misconfiguration.
 *
 * Assumes: only concrete, greppable misconfigurations are reported to avoid noise, such as debug mode
 * enabled, permissive CORS wildcards, and placeholder/empty secrets. Route-level auth and header
 * middleware presence are intentionally not asserted here to keep the signal conservative.
 */
final class OwaspMisconfigurationAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_MISCONFIGURATION';

    // Only scan real config files, not tests/seeders/demo data (too noisy).
    private const CONFIG_FILES = [
        'app.php', 'cors.php', 'database.php', 'mail.php', 'queue.php',
        'session.php', 'auth.php', 'services.php', '.env', '.env.example',
    ];

    private const PLACEHOLDER_MARKERS = [
        'changeme', 'your-password', 'your_secret', 'replace_me', 'changeme123',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if (!$this->isConfigFile($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function isConfigFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);
        $basename = strtolower(pathinfo($file, PATHINFO_BASENAME));

        // Real Laravel config files live under /config/.
        if (str_contains($normalized, '/config/')) {
            return true;
        }

        // Allow .env files at project root only.
        return in_array($basename, ['.env', '.env.example'], true);
    }

    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $issues = [];
        $lines = explode("\n", $code);

        foreach ($lines as $index => $line) {
            $trimmed = trim($line);
            $lineNo = $index + 1;

            if ($this->isDebugEnabled($trimmed)) {
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Debug mode is enabled in production configuration.',
                    $file,
                    $lineNo,
                    Severity::Warning,
                    ['kind' => 'debug']
                );
                continue;
            }

            if ($this->isPermissiveCors($trimmed)) {
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Permissive CORS configuration detected (wildcard origin).',
                    $file,
                    $lineNo,
                    Severity::Warning,
                    ['kind' => 'cors']
                );
                continue;
            }

            if ($this->isPlaceholderSecret($trimmed)) {
                $issues[] = $this->makeIssue(
                    self::RULE,
                    'Possible placeholder or empty secret detected.',
                    $file,
                    $lineNo,
                    Severity::Warning,
                    ['kind' => 'placeholder']
                );
            }
        }

        return $issues;
    }

    private function isDebugEnabled(string $line): bool
    {
        if (preg_match('/\'debug\'\s*=>\s*true/i', $line)) {
            return true;
        }

        if (preg_match('/APP_DEBUG\s*=\s*true/i', $line)) {
            return true;
        }

        if (preg_match('/APP_DEBUG\s*=\s*(?!false|0)\S+/i', $line)) {
            return true;
        }

        return false;
    }

    private function isPermissiveCors(string $line): bool
    {
        if (preg_match('/allowed_origins\'\s*=>\s*\[\s*\'\*\'\s*\]/i', $line)) {
            return true;
        }

        if (preg_match('/allowed_origins_patterns\'\s*=>\s*\[\s*\'\*\'\s*\]/i', $line)) {
            return true;
        }

        if (
            preg_match('/allowed_origins\s*=>\s*\'\*\'\s*[,\)]/i', $line)
            || preg_match('/allowed_origins_patterns\s*=>\s*\'\*\'\s*[,\)]/i', $line)
        ) {
            return true;
        }

        return false;
    }

    private function isPlaceholderSecret(string $line): bool
    {
        // Only flag an empty value for the actual app encryption key or DB password,
        // which are genuinely dangerous. Avoid generic 'password' => '' in demo/test data.
        if (preg_match('/\'(key|APP_KEY|DB_PASSWORD)\'\s*=>\s*\'\'\s*[,\)]/i', $line)) {
            return true;
        }
        if (preg_match('/^(APP_KEY|DB_PASSWORD)\s*=\s*[\'\"]?\s*[\'\"]?\s*$/i', $line)) {
            return true;
        }

        foreach (self::PLACEHOLDER_MARKERS as $marker) {
            if (stripos($line, $marker) !== false) {
                return true;
            }
        }

        return false;
    }
}
