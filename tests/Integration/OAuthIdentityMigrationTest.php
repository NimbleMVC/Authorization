<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Config;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;

final class OAuthIdentityMigrationTest extends TestCase
{
    public function testMigrationEnforcesUniqueProviderAndSubjectPair(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($pdo);
        Config::$tableName = 'custom_accounts';
        Config::$oauthColumns = ['provider' => 'issuer', 'id' => 'external_id'];
        $pdo->exec('CREATE TABLE custom_accounts (id INTEGER PRIMARY KEY, issuer TEXT, external_id TEXT)');

        $migration = require dirname(__DIR__, 2) . '/src/Migrations/1784368700.php';
        $migration->run();
        $pdo->exec("INSERT INTO custom_accounts (issuer, external_id) VALUES ('github', '123')");

        $this->expectException(PDOException::class);

        try {
            $pdo->exec("INSERT INTO custom_accounts (issuer, external_id) VALUES ('github', '123')");
        } finally {
            Config::$tableName = 'accounts';
            Config::$oauthColumns = [
                'id' => 'account_oauth_id',
                'provider' => 'account_oauth_provider',
            ];
        }
    }
}
