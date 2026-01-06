<?php

namespace NimblePHP\Authorization;

use krzysztofzylka\DatabaseManager\Exception\ConnectException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use NimblePHP\Authorization\Middlewares\AuthorizationMiddleware;
use NimblePHP\Framework\Exception\DatabaseException;
use NimblePHP\Framework\Exception\NimbleException;
use NimblePHP\Framework\Interfaces\ServiceProviderInterface;
use NimblePHP\Framework\Interfaces\ServiceProviderUpdateInterface;
use NimblePHP\Framework\Kernel;
use NimblePHP\Migrations\Exceptions\MigrationException;
use NimblePHP\Migrations\Migrations;
use Throwable;

/**
 * ServiceProvider class - Service provider for Authorization library integration
 * 
 * This class is responsible for:
 * - Running database migrations for Authorization tables
 * - Initializing the Authorization module in NimblePHP framework
 * - Setting up required database schema on application update
 * 
 * @package NimblePHP\Authorization
 */
class ServiceProvider implements ServiceProviderUpdateInterface, ServiceProviderInterface
{

    /**
     * Register module
     * @return void
     */
    public function register(): void
    {
        Config::init();
        Kernel::$middlewareManager->add(new AuthorizationMiddleware(), Config::$middlewarePriority);
    }

    /**
     * Execute on application update - runs pending migrations
     * @return void
     * @throws DatabaseException
     * @throws NimbleException
     * @throws MigrationException
     * @throws Throwable
     * @throws ConnectException
     * @throws DatabaseManagerException
     */
    public function onUpdate(): void
    {
        Config::init();
        $migration = new Migrations(Kernel::$projectPath, __DIR__ . '/Migrations', 'module_authorization');
        $migration->runMigrations();
    }

}