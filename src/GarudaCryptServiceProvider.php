<?php

namespace Soden46\GarudaCrypt;

use Illuminate\Support\ServiceProvider;
use Soden46\GarudaCrypt\Commands\GarudaCryptPublishCommand;

class GarudaCryptServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/config.php' => config_path('config.php'),
            ], 'garuda-config');

            $this->commands([
                GarudaCryptPublishCommand::class,
            ]);
        }
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/config.php', 'garudacrypt');
    }
}
