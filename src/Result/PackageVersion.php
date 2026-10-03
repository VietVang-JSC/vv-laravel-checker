<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Result;

/**
 * Resolves the version string printed in every report header.
 *
 * Two entry points produce reports — `php artisan quality:check` and
 * `bin/quality-check` — and they disagreed: the Artisan command read
 * composer.json, the standalone runner never set it at all, so every
 * standalone report was stamped `v0.0.0` (CheckContext's default) while the
 * same code path in a Laravel app showed a real version. A version field in a
 * report is what a reader uses to tell "this scan ran on 0.7.0" from "this scan
 * ran on last week's main", so both paths must go through here.
 *
 * Resolution order:
 *  1. composer.json `version` — set only when a maintainer pins it (Composer
 *     injects it for tagged installs; a hardcoded field would override the tag).
 *  2. Composer's runtime `InstalledVersions` — the authoritative answer for an
 *     installed package (`v0.7.0`), and `dev-main` for a git checkout.
 *  3. `FALLBACK` — only when the package runs without Composer metadata.
 */
final class PackageVersion
{
    public const FALLBACK = '0.0.0';

    /**
     * @param string|null $packageRoot directory holding composer.json; defaults
     *                                  to the installed package root
     */
    public static function detect(?string $packageRoot = null): string
    {
        return self::fromComposerJson($packageRoot)
            ?? self::fromInstalledVersions()
            ?? self::FALLBACK;
    }

    /**
     * Display form: `v0.7.0` for a release, `dev-main` unchanged. Reporters used
     * to concatenate a literal `v`, which turned a branch checkout into
     * `vdev-main`.
     */
    public static function label(string $version): string
    {
        return preg_match('/^\d/', $version) === 1 ? 'v' . $version : $version;
    }

    private static function fromComposerJson(?string $packageRoot): ?string
    {
        $root = $packageRoot ?? dirname(__DIR__, 2);
        $file = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($file)) {
            return null;
        }

        $data = json_decode((string) file_get_contents($file), true);
        if (!is_array($data) || !isset($data['version']) || !is_string($data['version'])) {
            return null;
        }

        $version = trim($data['version']);

        return $version === '' ? null : $version;
    }

    private static function fromInstalledVersions(): ?string
    {
        if (!class_exists(\Composer\InstalledVersions::class)) {
            return null;
        }

        try {
            $version = \Composer\InstalledVersions::getPrettyVersion('rampart/quality-checker');
        } catch (\OutOfBoundsException) {
            return null;
        }

        if (!is_string($version) || $version === '') {
            return null;
        }

        return ltrim($version, 'v');
    }
}
