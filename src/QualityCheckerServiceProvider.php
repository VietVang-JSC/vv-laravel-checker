<?php

declare(strict_types=1);

namespace Rampart\QualityChecker;

use Illuminate\Support\ServiceProvider;
use Rampart\QualityChecker\Commands\QualityCheckCommand;

final class QualityCheckerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/quality-checker.php', 'quality-checker');

        $this->commands([
            QualityCheckCommand::class,
        ]);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/quality-checker.php' => config_path('quality-checker.php'),
            ], 'quality-checker-config');
        }
    }
}
