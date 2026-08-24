<?php

declare(strict_types=1);

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * AUT-M05: adds the columns RememberMeService needs to consume a rotation
 * atomically and detect reuse of an already-rotated-away token.
 *
 * - `used_at`: set by an atomic conditional UPDATE when a token is consumed
 *   on rotation, instead of the previous read-then-delete race.
 * - `family_id`: shared by every token issued through one continuous chain
 *   of rotations, so a validator match against a token whose `used_at` is
 *   already set can be recognised as reuse (theft) rather than a fresh login.
 */
return new class extends AbstractMigration {
    public function run(): void
    {
        if (!(new Table(Config::$rememberMeTableName))->exists()) {
            return;
        }

        $pdo = DatabaseManager::$connection->getConnection();
        $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $quote = $driver === 'pgsql' ? '"' : '`';
        $table = $quote . Config::$rememberMeTableName . $quote;

        $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$quote}used_at{$quote} DATETIME NULL");
        $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$quote}family_id{$quote} VARCHAR(32) NULL");
    }
};
