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
    ];

    private const HEX_PATTERN = '/\\\\x[0-9a-f]{2}/i';

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
            // Match call patterns against code with string literals and
            // comments stripped: pattern names inside docs, remediation
            // text or this analyzer's own labels are not backdoors
            // (self-scan used to flag OBFUSCATED_PHP on its own source).
            $stripped = self::stripStringsAndComments($code);
            foreach (self::PATTERNS as $pattern => $label) {
                if (preg_match($pattern, $stripped) === 1) {
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
            if ($issues !== []) {
                continue;
            }
            // Hex escapes live inside string literals by definition, so
            // stripping would blind this check. Require density instead:
            // real payloads carry runs of escapes; short legit runs
            // (BOM `\xEF\xBB\xBF`, newlines) stay silent below 4.
            if (preg_match_all(self::HEX_PATTERN, $code) >= 4) {
                $issues[] = new Issue(
                    self::RULE,
                    'Obfuscated PHP detected: hex-encoded string.',
                    $file,
                    1,
                    Severity::Critical,
                    'custom',
                    ['pattern' => self::HEX_PATTERN],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    /**
     * Code with string literals, comments and HTML dropped, tokenized
     * with the native lexer (no extra dependency). Snippets without an
     * open tag lex as inline HTML, so a synthetic tag is prepended.
     */
    private static function stripStringsAndComments(string $code): string
    {
        if (!str_contains($code, '<?')) {
            $code = '<?php ' . $code;
        }
        $out = '';
        foreach (token_get_all($code) as $token) {
            if (is_string($token)) {
                $out .= $token . ' ';
                continue;
            }
            [$id, $text] = $token;
            if (in_array($id, [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML], true)) {
                $out .= ' ';
                continue;
            }
            $out .= $text . ' ';
        }

        return $out;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }
}
