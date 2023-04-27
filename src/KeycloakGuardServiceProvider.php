<?php

namespace g4t\Keycloak;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Kreait\LaravelKeycloak\Facades\Keycloak;

class KeycloakGuardServiceProvider extends ServiceProvider
{

    /**
     * Bootstrap services.
     */
    public function boot()
    {
        $this->publishes([__DIR__.'/../config/g4t-keycloak.php' => config_path('g4t-keycloak.php')], 'config');
        $this->mergeConfigFrom(__DIR__.'/../config/g4t-keycloak.php', 'g4t-keycloak');
    }


    /**
     * Register services.
     */
    public function register()
    {
        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(Auth::createUserProvider($config['provider']));
        });
    }

}




