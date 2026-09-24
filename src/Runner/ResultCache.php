<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Runner;

final class ResultCache
{
    private string $cacheDir;

    private static ?string $codeVersion = null;

    public function __construct(CheckContext $ctx)
    {
        $this->cacheDir = rtrim($ctx->outputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.cache';
    }

    public function get(string $key): ?array
    {
        $path = $this->pathFor($key);
        if (!is_file($path)) {
            return null;
        }

        $raw = (string) file_get_contents($path);
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return null;
        }

        $expiresAt = (int) ($data['expires_at'] ?? 0);
        if ($expiresAt > 0 && $expiresAt < time()) {
            @unlink($path);

            return null;
        }

        $payload = $data['data'] ?? null;

        return is_array($payload) ? $payload : null;
    }

    public function put(string $key, array $data, int $ttl): void
    {
        if (!is_dir($this->cacheDir) && !@mkdir($this->cacheDir, 0777, true) && !is_dir($this->cacheDir)) {
            return;
        }

        $payload = [
            'expires_at' => time() + $ttl,
            'created_at' => time(),
            'data' => $data,
        ];

        file_put_contents($this->pathFor($key), json_encode($payload));
    }

    public function clear(): void
    {
        if (!is_dir($this->cacheDir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->cacheDir, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile()) {
                @unlink($file->getPathname());
            }
        }
    }

    public function key(string $checkerName, array $paths, array $configHash): string
    {
        return md5(
            $checkerName . '|' . implode(',', $paths) . '|' . md5(serialize($configHash))
            . '|' . self::codeVersion()
        );
    }

    /**
     * Version of the analyzer/checker code, baked into every cache key so a
     * package upgrade can never serve results computed by older analyzers.
     */
    public static function codeVersion(): string
    {
        if (self::$codeVersion !== null) {
            return self::$codeVersion;
        }

        $root = dirname(__DIR__, 2);
        $hashes = [];
        foreach (['src/Analyzers', 'src/Checkers', 'src/Runner'] as $dir) {
            $abs = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $dir);
            if (!is_dir($abs)) {
                continue;
            }
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($abs, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                if (strtolower($file->getExtension()) !== 'php') {
                    continue;
                }
                $hashes[$file->getPathname()] = md5((string) file_get_contents($file->getPathname()));
            }
        }
        ksort($hashes);

        self::$codeVersion = md5(implode('|', $hashes));

        return self::$codeVersion;
    }

    private function pathFor(string $key): string
    {
        return $this->cacheDir . DIRECTORY_SEPARATOR . $key . '.json';
    }
}
