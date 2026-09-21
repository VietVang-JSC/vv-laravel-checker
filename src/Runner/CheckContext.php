<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Runner;

final class CheckContext
{
    public string $basePath;

    /** @var list<string> */
    public array $paths;

    /** @var array<string, mixed> */
    public array $config;

    public string $outputDir;

    public bool $noCache;

    public bool $noAutoInstall;

    public bool $ci;

    public bool $quiet;

    public string $packageVersion;

    public string $failOn;

    public string $tier;

    public string $minConfidence;

    public int $exitCode = 0;

    /** @var list<string> checker names to run; empty means all */
    public array $only = [];

    /** @var list<string> checker names to skip */
    public array $exclude = [];

    public ?string $baselineFile = null;

    public bool $fix = false;

    /** @var array<string, mixed> */
    public array $metadata = [];

    /**
     * @param list<string> $paths
     * @param array<string, mixed> $config
     * @param list<string> $only
     * @param list<string> $exclude
     */
    public function __construct(
        string $basePath,
        array $paths,
        array $config,
        string $outputDir,
        bool $noCache = false,
        bool $ci = false,
        bool $quiet = false,
        string $packageVersion = '0.0.0',
        string $failOn = 'error',
        array $only = [],
        array $exclude = [],
        string $tier = 'quality',
        string $minConfidence = 'low',
        bool $noAutoInstall = false,
    ) {
        $this->basePath = rtrim($basePath, '/\\');
        $this->paths = array_values(array_filter($paths, static fn ($p): bool => is_string($p) && $p !== ''));
        $this->config = $config;
        $this->outputDir = $outputDir;
        $this->noCache = $noCache;
        $this->noAutoInstall = $noAutoInstall;
        $this->ci = $ci;
        $this->quiet = $quiet;
        $this->packageVersion = $packageVersion;
        $this->failOn = $failOn;
        $this->only = $only;
        $this->exclude = $exclude;
        $this->tier = $tier;
        $this->minConfidence = $minConfidence;
    }

    /**
     * Resolve a path to an absolute filesystem path.
     */
    public function resolvePath(string $path): string
    {
        if ($this->isAbsolute($path)) {
            return $path;
        }

        return $this->basePath . DIRECTORY_SEPARATOR . $path;
    }

    public function configFor(string $key, array $default = []): array
    {
        $value = $this->config[$key] ?? null;

        return is_array($value) ? array_merge($default, $value) : $default;
    }

    private function isAbsolute(string $path): bool
    {
        if ($path === '') {
            return false;
        }

        if (DIRECTORY_SEPARATOR === '/' && str_starts_with($path, '/')) {
            return true;
        }

        if (preg_match('/^[A-Za-z]:[\\\\\\/]/', $path) === 1) {
            return true;
        }

        return str_starts_with($path, '\\\\');
    }
}
