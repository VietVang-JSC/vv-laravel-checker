<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Runner\CheckContext;
use Rampart\QualityChecker\Tools\ToolInstaller;

final class ToolInstallerTest extends TestCase
{
    /**
     * @param array<string, mixed> $config
     */
    private function context(bool $noAutoInstall = false, array $config = []): CheckContext
    {
        return new CheckContext(
            sys_get_temp_dir(),
            ['app'],
            $config,
            sys_get_temp_dir() . '/r',
            noAutoInstall: $noAutoInstall,
        );
    }

    public function testCanInstallKnownComposerTools(): void
    {
        $installer = new ToolInstaller($this->context(config: ['auto_install_tools' => true]));

        self::assertTrue($installer->canInstall('phpcs'));
        self::assertTrue($installer->canInstall('phpstan'));
        self::assertTrue($installer->canInstall('phpunit'));
        self::assertTrue($installer->canInstall('trivy'));
    }

    public function testCannotInstallUnknownTool(): void
    {
        $installer = new ToolInstaller($this->context(config: ['auto_install_tools' => true]));

        self::assertFalse($installer->canInstall('grumphp'));
        self::assertFalse($installer->canInstall('custom'));
    }

    public function testDisabledByNoAutoInstallFlag(): void
    {
        $installer = new ToolInstaller($this->context(noAutoInstall: true));

        self::assertFalse($installer->enabled());
        self::assertFalse($installer->canInstall('phpcs'));
    }

    public function testDisabledByConfig(): void
    {
        $installer = new ToolInstaller($this->context(config: ['auto_install_tools' => false]));

        self::assertFalse($installer->enabled());
        self::assertFalse($installer->canInstall('phpcs'), 'A disabled installer must not offer to install.');
    }

    /**
 * No config key at all means no install. Installing is `composer require --dev`
 * inside the caller's repo, so the safe reading of "unset" is "off" — a
 * programmatic context (tests, or a target with no config file) must not mutate
 * a repository it was only asked to inspect.
 */
    public function testUnsetConfigMeansDisabled(): void
    {
        $installer = new ToolInstaller($this->context());

        self::assertFalse(
            $installer->enabled(),
            'auto-install defaulted to on when no config key was present.'
        );
        self::assertFalse($installer->canInstall('phpcs'));
    }

    public function testEnabledExplicitlyByConfig(): void
    {
        $installer = new ToolInstaller($this->context(config: ['auto_install_tools' => true]));

        self::assertTrue($installer->enabled());
        self::assertTrue($installer->canInstall('phpcs'));
    }

    public function testHintProvidesInstallCommand(): void
    {
        $installer = new ToolInstaller($this->context());

        self::assertStringContainsString('php_codesniffer', $installer->hint('phpcs'));
        self::assertStringContainsString('phpstan/phpstan', $installer->hint('phpstan'));
        self::assertStringContainsString('phpunit/phpunit', $installer->hint('phpunit'));
        self::assertStringContainsString('aquasecurity/trivy', $installer->hint('trivy'));
    }
}
