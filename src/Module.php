<?php

namespace NimblePHP\Authorization;

use NimblePHP\Authorization\Middlewares\AuthorizationMiddleware;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Module\Interfaces\ModuleInterface;
use NimblePHP\Framework\Module\Interfaces\ModuleUpdateInterface;
use krzysztofzylka\DatabaseManager\Exception\ConnectException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use NimblePHP\Framework\Exception\DatabaseException;
use NimblePHP\Framework\Exception\NimbleException;
use NimblePHP\Framework\Translation\Translation;
use NimblePHP\Framework\Translation\TranslationProviderInterface;
use NimblePHP\Migrations\Exceptions\MigrationException;
use NimblePHP\Migrations\Migrations;
use Throwable;

class Module implements ModuleInterface, ModuleUpdateInterface, TranslationProviderInterface
{

    public function getName(): string
    {
        return 'Authorization for nimblephp';
    }

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

    /**
     * @return void
     */
    public function registerTranslations(): void
    {
        Translation::getInstance()->addTranslationPath(__DIR__ . '/Lang', Translation::PRIORITY_MODULE);
    }

}