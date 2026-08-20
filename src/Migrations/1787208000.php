<?php

declare(strict_types=1);

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Migrations\AbstractMigration;

/**
 * AUT-H06: adds the columns APIKeyProvider needs to enforce the per-key
 * rate limit atomically (a single conditional UPDATE) instead of only
 * reporting it.
 */
return new class extends AbstractMigration {
    public function run(): void
    {
        if (!(new Table('account_api_keys'))->exists()) {
            return;
        }

        $pdo = DatabaseManager::$connection->getConnection();
        $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $quote = $driver === 'pgsql' ? '"' : '`';
        $table = $quote . 'account_api_keys' . $quote;

        $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$quote}rate_window_started_at{$quote} DATETIME NULL");
        $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$quote}rate_window_count{$quote} INTEGER NOT NULL DEFAULT 0");
    }
};
