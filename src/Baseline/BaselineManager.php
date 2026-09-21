<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Baseline;

/**
 * Baseline support for known/accepted issues.
 *
 * A baseline is a JSON file (default `baseline.json` at the project root, or
 * the path returned by config key `baseline.file` when present) that contains a
 * flat list of issue signatures. A signature is `md5(rule|file|line|message)`.
 *
 * Assumptions:
 *  - The file, when present, is either a bare JSON array of signature strings,
 *    or an object `{"baseline": [...]}` for forward compatibility with config.
 *  - `load()` returns an empty set (never throws) when the file is missing or
 *    unreadable.
 *  - Signatures are compared on the fully-qualified `rule`, absolute `file`
 *    path, integer `line`, and exact `message`.
 */
final class BaselineManager
{
    private const DEFAULT_FILENAME = 'baseline.json';

    /** @var array<string, true> */
    private array $signatures = [];

    private ?string $baselineFile;

    public function __construct(?string $baselineFile = null)
    {
        $this->baselineFile = $baselineFile;
    }

    /**
     * Load a baseline file. Returns an empty set when the file does not exist.
     *
     * @return array<string, string> signature => signature
     */
    public function load(?string $baselineFile = null): array
    {
        $file = $baselineFile ?? $this->baselineFile;
        if ($file === null || !is_file($file)) {
            return [];
        }

        $raw = file_get_contents($file);
        if ($raw === false) {
            return [];
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }

        $list = $decoded['baseline'] ?? $decoded;

        $loaded = [];
        if (is_array($list)) {
            foreach ($list as $sig) {
                if (is_string($sig) && $sig !== '') {
                    $loaded[$sig] = $sig;
                }
            }
        }

        $this->signatures = $loaded;

        return $this->signatures;
    }

    /**
     * Returns true when the given issue's signature is present in the baseline.
     */
    public function isBaselined(array $issue): bool
    {
        $sig = $this->signature($issue);

        return $sig !== null && isset($this->signatures[$sig]);
    }

    /**
     * Deduplicate a list of issues into an array of unique signatures.
     *
     * @param list<array<string, mixed>> $results Issue[] (may include nested `issues`).
     * @return array<string, string> signature => signature
     */
    public function generateBaseline(array $results): array
    {
        $signatures = [];

        foreach ($results as $result) {
            $issues = is_array($result) && isset($result['issues']) && is_array($result['issues'])
                ? $result['issues']
                : [$result];

            foreach ($issues as $issue) {
                if (!is_array($issue)) {
                    continue;
                }
                $sig = $this->signature($issue);
                if ($sig !== null) {
                    $signatures[$sig] = $sig;
                }
            }
        }

        return $signatures;
    }

    /**
     * Write the given issues as a new baseline, overwriting the file.
     *
     * @param array $results Issue[] or CheckResult[] (as accepted by generateBaseline).
     */
    public function update(array $results, string $baselineFile): void
    {
        $signatures = $this->generateBaseline($results);
        $this->signatures = $signatures;

        $dir = dirname($baselineFile);
        if ($dir !== '' && !is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        $payload = json_encode(
            [
                'generated_at' => (new \DateTimeImmutable())->format(DATE_ATOM),
                'baseline' => array_values($signatures),
            ],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );

        file_put_contents($baselineFile, $payload . PHP_EOL);
    }

    /**
     * Build the canonical signature for an issue, or null when insufficient data.
     */
    public function signature(array $issue): ?string
    {
        $rule = $issue['rule'] ?? null;
        $file = $issue['file'] ?? null;
        $line = $issue['line'] ?? null;
        $message = $issue['message'] ?? null;

        if (!is_string($rule) || !is_string($file) || !is_string($message)) {
            return null;
        }

        $lineNorm = is_int($line) ? $line : 0;

        return md5($rule . '|' . $file . '|' . $lineNorm . '|' . $message);
    }
}
