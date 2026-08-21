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

/** AUT-M04: the unique index on `identifier` is required for the atomic UPSERT in increment(). */
final class RateLimitMigrationTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);
        Config::$rateLimitTableName = 'account_rate_limits';

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_attempt INTEGER NOT NULL,
                last_attempt INTEGER NOT NULL,
                locked_until INTEGER NULL
            )
            SQL);
    }

    public function testMigrationEnforcesUniqueIdentifier(): void
    {
        $migration = require dirname(__DIR__, 2) . '/src/Migrations/1787209000.php';
        $migration->run();

        $this->pdo->exec("INSERT INTO account_rate_limits (identifier, attempts, first_attempt, last_attempt) VALUES ('a', 1, 1, 1)");

        $this->expectException(PDOException::class);
        $this->pdo->exec("INSERT INTO account_rate_limits (identifier, attempts, first_attempt, last_attempt) VALUES ('a', 1, 1, 1)");
    }

    public function testMigrationDeduplicatesPreExistingDuplicatesBeforeIndexing(): void
    {
        // Simulates rows a pre-AUT-M04 race could have produced.
        $this->pdo->exec("INSERT INTO account_rate_limits (identifier, attempts, first_attempt, last_attempt) VALUES ('dup', 3, 100, 130)");
        $this->pdo->exec("INSERT INTO account_rate_limits (identifier, attempts, first_attempt, last_attempt) VALUES ('dup', 1, 200, 200)");
        $this->pdo->exec("INSERT INTO account_rate_limits (identifier, attempts, first_attempt, last_attempt) VALUES ('other', 1, 50, 50)");

        $migration = require dirname(__DIR__, 2) . '/src/Migrations/1787209000.php';
        $migration->run();

        $rows = $this->pdo->query("SELECT id, identifier FROM account_rate_limits ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);

        self::assertCount(2, $rows);
        self::assertSame(['dup', 'other'], array_column($rows, 'identifier'));

        // The kept "dup" row is the highest id (most recently created) one.
        $kept = $this->pdo->query("SELECT attempts FROM account_rate_limits WHERE identifier = 'dup'")->fetch(PDO::FETCH_ASSOC);
        self::assertSame(1, (int)$kept['attempts']);
    }
}
