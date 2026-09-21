<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tools;

use Symfony\Component\Process\Process;
use VietVang\QualityChecker\Runner\CheckContext;

/**
 * Self-provisioning of missing CLI tools.
 *
 * Installs composer-based tools (phpcs, phpstan, phpunit) via `composer require --dev`
 * inside the target project, and downloads the Trivy binary via TrivyDownloader.
 * Runs automatically (no user prompt) unless `auto_install_tools` is disabled.
 */
final class ToolInstaller
{
    /** checker name => composer dev package */
    private const COMPOSER_TOOLS = [
        'phpcs' => 'squizlabs/php_codesniffer',
        'phpstan' => 'phpstan/phpstan',
        'phpunit' => 'phpunit/phpunit',
    ];

    private CheckContext $ctx;

    public function __construct(CheckContext $ctx)
    {
        $this->ctx = $ctx;
    }

    /**
     * Whether auto-install is allowed at all (config + flag).
     */
    public function enabled(): bool
    {
        if ($this->ctx->noAutoInstall) {
            return false;
        }

        return (bool) ($this->ctx->config['auto_install_tools'] ?? true);
    }

    /**
     * Whether we can install the given checker's tool.
     */
    public function canInstall(string $checkerName): bool
    {
        if (!$this->enabled()) {
            return false;
        }

        return isset(self::COMPOSER_TOOLS[$checkerName]) || $checkerName === 'trivy';
    }

    /**
     * Install the tool for a checker. Returns true when the tool became available.
     */
    public function install(string $checkerName): bool
    {
        if (isset(self::COMPOSER_TOOLS[$checkerName])) {
            return $this->installComposerTool(self::COMPOSER_TOOLS[$checkerName]);
        }

        if ($checkerName === 'trivy') {
            return (new TrivyDownloader($this->ctx))->binaryPath() !== null;
        }

        return false;
    }

    /**
     * Resolve the binary path for a checker after (potential) install.
     */
    public function binaryPath(string $checkerName): ?string
    {
        if ($checkerName === 'trivy') {
            return (new TrivyDownloader($this->ctx))->binaryPath();
        }

        return null;
    }

    /**
     * Human-readable manual install hint for a checker.
     */
    public function hint(string $checkerName): string
    {
        return match ($checkerName) {
            'phpcs' => 'composer require --dev squizlabs/php_codesniffer',
            'phpstan' => 'composer require --dev phpstan/phpstan',
            'phpunit' => 'composer require --dev phpunit/phpunit',
            'trivy' => 'download from https://github.com/aquasecurity/trivy/releases or run this tool online',
            default => 'install the missing tool',
        };
    }

    private function installComposerTool(string $package): bool
    {
        $composer = $this->findComposer();
        if ($composer === null) {
            return false;
        }

        $command = [
            $composer,
            'require',
            '--dev',
            $package,
            '--no-interaction',
            '--no-progress',
            '--no-scripts',
            '--no-plugins',
        ];

        $process = new Process($command, $this->ctx->basePath);
        $process->setTimeout(600.0);
        $process->run();

        return $process->isSuccessful();
    }

    private function findComposer(): ?string
    {
        // Look for a local composer.phar first, then fall back to PATH `composer`.
        $phar = $this->ctx->basePath . DIRECTORY_SEPARATOR . 'composer.phar';
        if (is_file($phar)) {
            return PHP_BINARY . ' ' . $phar;
        }

        $which = PHP_OS_FAMILY === 'Windows' ? 'where' : 'which';
        $process = new Process([$which, 'composer']);
        $process->run();

        return $process->isSuccessful() ? 'composer' : null;
    }
}
