<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tools;

use Symfony\Component\Process\Process;
use Rampart\QualityChecker\Runner\CheckContext;

/**
 * Self-provisioning of missing CLI tools.
 *
 * Installs composer-based tools (phpcs, phpstan, phpunit) via `composer require --dev`
 * inside the target project, and downloads the Trivy binary via TrivyDownloader.
 * Runs automatically (no user prompt) unless `auto_install_tools` is disabled.
 */
final class ToolInstaller
{
    /**
     * Checker name => composer package, with the version range this package has
     * actually been verified against.
     *
     * The constraint is deliberate. Installing `squizlabs/php_codesniffer` with
     * no range means a fresh project gets phpcs 4.x, whose PSR12 ruleset also
     * reports `Squiz.*` codes — a legitimate change in the tool's output that
     * the JSON contract below still parses, but that a user would experience as
     * new findings with no cause. Stating `^3.13 || ^4.0` documents the tested
     * range and makes an untested future major a visible conflict instead of a
     * silent behaviour change in someone's build.
     *
     * @var array<string, string>
     */
    private const COMPOSER_TOOLS = [
        'phpcs' => 'squizlabs/php_codesniffer:^3.13 || ^4.0',
        'phpstan' => 'phpstan/phpstan:^2.0',
        'phpunit' => 'phpunit/phpunit:^10.5 || ^11.0',
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
            'phpcs' => 'composer require --dev "squizlabs/php_codesniffer:^3.13 || ^4.0"',
            'phpstan' => 'composer require --dev "phpstan/phpstan:^2.0"',
            'phpunit' => 'composer require --dev "phpunit/phpunit:^10.5 || ^11.0"',
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

        $command = array_merge(
            $composer,
            [
                'require',
                '--dev',
                $package,
                '--no-interaction',
                '--no-progress',
                '--no-scripts',
                '--no-plugins',
            ]
        );

        $process = new Process($command, $this->ctx->basePath);
        $process->setTimeout(600.0);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * The composer command as a *list*, never a joined string.
     *
     * `Symfony\Component\Process\Process` executes element 0 as the binary and
     * passes the rest as arguments. A local `composer.phar` has to be run as
     * `php composer.phar`, which is two elements; returning
     * `PHP_BINARY . ' ' . $phar` produced a single element naming a file that
     * does not exist, so the spawn failed with exit 127 and auto-install
     * silently reported failure on every project that ships its own phar.
     *
     * @return list<string>|null
     */
    private function findComposer(): ?array
    {
        // Look for a local composer.phar first, then fall back to PATH `composer`.
        $phar = $this->ctx->basePath . DIRECTORY_SEPARATOR . 'composer.phar';
        if (is_file($phar)) {
            return [PHP_BINARY, $phar];
        }

        $which = PHP_OS_FAMILY === 'Windows' ? 'where' : 'which';
        $process = new Process([$which, 'composer']);
        $process->run();

        return $process->isSuccessful() ? ['composer'] : null;
    }
}
