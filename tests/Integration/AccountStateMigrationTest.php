<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Config;
use PDO;
use PHPUnit\Framework\TestCase;

final class AccountStateMigrationTest extends TestCase
{
    public function testMigrationAddsCredentialEpochToConfiguredAccountsAndApiKeys(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($pdo);
        Config::$tableName = 'custom_accounts';
        Config::$columns['auth_epoch'] = 'credential_version';

        $pdo->exec('CREATE TABLE custom_accounts (id INTEGER PRIMARY KEY, active INTEGER NOT NULL)');
        $pdo->exec('CREATE TABLE account_api_keys (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL)');

        $migration = require dirname(__DIR__, 2) . '/src/Migrations/1784369500.php';
        $migration->run();

        $accountColumns = $pdo->query('PRAGMA table_info(custom_accounts)')->fetchAll(PDO::FETCH_ASSOC);
        $apiKeyColumns = $pdo->query('PRAGMA table_info(account_api_keys)')->fetchAll(PDO::FETCH_ASSOC);

        self::assertContains('credential_version', array_column($accountColumns, 'name'));
        self::assertContains('auth_epoch', array_column($apiKeyColumns, 'name'));

        $pdo->exec('INSERT INTO custom_accounts (id, active) VALUES (1, 1)');
        $pdo->exec('INSERT INTO account_api_keys (id, user_id) VALUES (1, 1)');
        self::assertSame(0, (int)$pdo->query(
            'SELECT credential_version FROM custom_accounts WHERE id = 1'
        )->fetchColumn());
        self::assertSame(0, (int)$pdo->query(
            'SELECT auth_epoch FROM account_api_keys WHERE id = 1'
        )->fetchColumn());

        Config::$tableName = 'accounts';
        Config::$columns['auth_epoch'] = 'auth_epoch';
    }
}
