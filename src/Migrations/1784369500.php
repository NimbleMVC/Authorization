<?php

declare(strict_types=1);

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/** Add the monotonically increasing credential epoch to accounts and API keys. */
return new class extends AbstractMigration {
    public function run(): void
    {
        $pdo = DatabaseManager::$connection->getConnection();
        $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $quote = $driver === 'pgsql' ? '"' : '`';
        $type = $driver === 'sqlite'
            ? 'INTEGER NOT NULL DEFAULT 0'
            : ($driver === 'pgsql' ? 'BIGINT NOT NULL DEFAULT 0' : 'BIGINT UNSIGNED NOT NULL DEFAULT 0');

        $accountTable = $this->identifier(Config::$tableName, $quote);
        $accountEpoch = $this->identifier(Config::getColumn('auth_epoch'), $quote);
        $pdo->exec("ALTER TABLE {$accountTable} ADD COLUMN {$accountEpoch} {$type}");

        if ((new Table('account_api_keys'))->exists()) {
            $apiKeyTable = $this->identifier('account_api_keys', $quote);
            $apiKeyEpoch = $this->identifier('auth_epoch', $quote);
            $pdo->exec("ALTER TABLE {$apiKeyTable} ADD COLUMN {$apiKeyEpoch} {$type}");
        }
    }

    private function identifier(string $identifier, string $quote): string
    {
        $parts = explode('.', $identifier);

        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $part)) {
                throw new InvalidArgumentException('Invalid account-state migration identifier');
            }
        }

        return implode('.', array_map(
            static fn(string $part): string => $quote . $part . $quote,
            $parts,
        ));
    }
};
