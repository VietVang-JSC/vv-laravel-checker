<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tools;

use Symfony\Component\Process\Process;
use VietVang\QualityChecker\Runner\CheckContext;

/**
 * Downloads and caches the Trivy security scanner binary.
 *
 * Trivy is a standalone Go binary (not a composer package), so we download a
 * pre-built release from GitHub into a per-user cache directory. The binary is
 * cached so repeated runs are offline and instant.
 *
 * Assumes: GitHub release assets follow the pattern
 *   trivy_<version>_<OS>-<ARCH>.(zip|tar.gz)
 * and that the local PHP has the required extensions to unzip (ZipArchive) or
 * that `unzip`/`tar` are available on the system.
 */
final class TrivyDownloader
{
    private const DEFAULT_VERSION = '0.74.0';
    private const RELEASE_BASE = 'https://github.com/aquasecurity/trivy/releases/download';

    private CheckContext $ctx;

    public function __construct(CheckContext $ctx)
    {
        $this->ctx = $ctx;
    }

    /**
     * Absolute path to a usable trivy binary, downloading it first if needed.
     */
    public function binaryPath(): ?string
    {
        $binary = $this->cachedBinary();
        if ($binary !== null && $this->isExecutable($binary)) {
            return $binary;
        }

        return $this->download();
    }

    private function download(): ?string
    {
        $version = $this->version();
        $os = $this->osName();
        $arch = $this->archName();
        $asset = sprintf('trivy_%s_%s-%s', $version, $os, $arch);
        $extension = PHP_OS_FAMILY === 'Windows' ? 'zip' : 'tar.gz';
        $url = sprintf('%s/v%s/%s.%s', self::RELEASE_BASE, $version, $asset, $extension);

        $cacheDir = $this->cacheDir();
        if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0777, true) && !is_dir($cacheDir)) {
            return null;
        }

        $archive = $cacheDir . DIRECTORY_SEPARATOR . $asset . '.' . $extension;
        if (!$this->httpGet($url, $archive)) {
            return null;
        }

        $extracted = $this->extract($archive, $cacheDir);
        @unlink($archive);

        $binary = $cacheDir . DIRECTORY_SEPARATOR . ($this->isWindows() ? 'trivy.exe' : 'trivy');
        if ($extracted && is_file($binary)) {
            @chmod($binary, 0755);

            return $binary;
        }

        return null;
    }

    private function cachedBinary(): ?string
    {
        $candidates = [
            $this->cacheDir() . DIRECTORY_SEPARATOR . ($this->isWindows() ? 'trivy.exe' : 'trivy'),
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate) && $this->isExecutable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    private function cacheDir(): string
    {
        // Per-user cache, outside the target project.
        $base = PHP_OS_FAMILY === 'Windows' && getenv('LOCALAPPDATA')
            ? getenv('LOCALAPPDATA')
            : (getenv('HOME') ?: sys_get_temp_dir());

        return rtrim($base, '/\\') . DIRECTORY_SEPARATOR . 'quality-checker' . DIRECTORY_SEPARATOR . 'trivy';
    }

    private function version(): string
    {
        $config = $this->ctx->config['trivy'] ?? [];

        return is_string($config['version'] ?? null) && $config['version'] !== ''
            ? (string) $config['version']
            : self::DEFAULT_VERSION;
    }

    private function osName(): string
    {
        // Trivy release assets use lowercase os names, e.g. `windows-64bit`,
        // `linux-64bit`, `macos-64bit`.
        return match (PHP_OS_FAMILY) {
            'Windows' => 'windows',
            'Darwin' => 'macos',
            default => 'linux',
        };
    }

    private function archName(): string
    {
        $machine = strtolower(PHP_INT_SIZE === 8 ? php_uname('m') : 'x86_64');

        return str_contains($machine, 'arm') || str_contains($machine, 'aarch64') ? 'ARM64' : '64bit';
    }

    private function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }

    private function isExecutable(string $path): bool
    {
        if ($this->isWindows()) {
            return is_file($path);
        }

        return is_file($path) && is_executable($path);
    }

    private function httpGet(string $url, string $dest): bool
    {
        $context = stream_context_create([
            'http' => ['follow_location' => 1, 'timeout' => 600],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);

        // Reviewed: $url is sprintf()'d from the RELEASE_BASE class constant
        // (fixed github.com host) plus a pinned version string.
        // quality-checker-ignore-next-line OWASP_SSRF,OWASP_PATH_TRAVERSAL
        $fp = @fopen($url, 'rb', false, $context);
        if ($fp === false) {
            return false;
        }

        // Reviewed: $dest is always inside our own cache dir ($cacheDir).
        // quality-checker-ignore-next-line OWASP_PATH_TRAVERSAL
        $out = @fopen($dest, 'wb');
        if ($out === false) {
            fclose($fp);

            return false;
        }

        $ok = stream_copy_to_stream($fp, $out) !== false;
        fclose($fp);
        fclose($out);

        return $ok;
    }

    private function extract(string $archive, string $dest): bool
    {
        if ($this->isWindows()) {
            if (class_exists('ZipArchive')) {
                $zip = new \ZipArchive();
                if ($zip->open($archive) === true) {
                    $zip->extractTo($dest);
                    $zip->close();

                    return true;
                }
            }

            // Fallback: PowerShell Expand-Archive.
            $ps = sprintf(
                'Expand-Archive -Path %s -DestinationPath %s -Force',
                escapeshellarg($archive),
                escapeshellarg($dest)
            );
            $process = new Process(['powershell', '-NoProfile', '-Command', $ps]);
            $process->run();

            return $process->isSuccessful();
        }

        $cmd = str_ends_with($archive, '.zip') ? ['unzip', '-o', $archive, '-d', $dest] : ['tar', '-xzf', $archive, '-C', $dest];
        $process = new Process($cmd);
        $process->run();

        return $process->isSuccessful();
    }
}
