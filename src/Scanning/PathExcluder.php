<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Scanning;

/**
 * Path-level exclusion for the custom analyzers.
 *
 * The scan used to have exactly one filter: a hardcoded skip-dir list
 * (`vendor`, `node_modules`, `storage`, `bootstrap/cache`, `.git`). There was no
 * way for a consumer to keep the analyzers away from a directory, because
 * `config.exclude` / `--exclude` filter *checker names*, not files. A project
 * with deliberately vulnerable fixtures under `tests/fixtures` — which is what
 * this package's own test suite is — had no option but to baseline the noise or
 * disable the rules outright.
 *
 * Dogfooding the tool on its own codebase made the cost concrete: 9 of the 11
 * findings were fixture code that exists to be vulnerable.
 *
 * Matching is case-insensitive and separator-insensitive (`\` is normalised to
 * `/`, so one pattern works on Windows and Linux). Two forms are accepted:
 *
 *  - glob: a pattern containing `*` or `?` is matched against the whole
 *    normalized path via `fnmatch()` (e.g. a leading-wildcard fixtures glob)
 *  - plain segment sequence: `tests/fixtures` matches anywhere in the path,
 *    but only on `/` boundaries — `fixtures` matches `/app/fixtures/x.php`
 *    and never `/app/fixturesx.php`.
 */
final class PathExcluder
{
    /** @var list<string> */
    private array $patterns;

    /**
     * @param list<string> $patterns
     */
    public function __construct(array $patterns = [])
    {
        $normalized = [];
        foreach ($patterns as $pattern) {
            if (!is_string($pattern)) {
                continue;
            }
            $pattern = trim(str_replace('\\', '/', $pattern));
            if ($pattern !== '') {
                $normalized[] = $pattern;
            }
        }

        $this->patterns = array_values(array_unique($normalized));
    }

    /**
     * @param array<string, mixed> $config the merged quality-checker config
     */
    public static function fromConfig(array $config): self
    {
        $patterns = $config['analyzers']['exclude_paths'] ?? [];

        return new self(is_array($patterns) ? $patterns : []);
    }

    public function isEmpty(): bool
    {
        return $this->patterns === [];
    }

    /**
     * @return list<string>
     */
    public function patterns(): array
    {
        return $this->patterns;
    }

    public function excludes(string $path): bool
    {
        if ($this->patterns === []) {
            return false;
        }

        $normalized = str_replace('\\', '/', $path);
        $lowerPath = strtolower($normalized);

        foreach ($this->patterns as $pattern) {
            if (str_contains($pattern, '*') || str_contains($pattern, '?')) {
                if (fnmatch(strtolower($pattern), $lowerPath)) {
                    return true;
                }
                continue;
            }

            $needle = '/' . trim(strtolower($pattern), '/') . '/';
            if (str_contains($lowerPath, $needle)) {
                return true;
            }
        }

        return false;
    }
}
