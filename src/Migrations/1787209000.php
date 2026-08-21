<?php

declare(strict_types=1);

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * AUT-M04: a unique index on `identifier` is required for
 * DatabaseRateLimiterStorage::increment() to upsert atomically
 * (INSERT ... ON CONFLICT/ON DUPLICATE KEY UPDATE).
 *
 * Without prior uniqueness, concurrent inserts could already have produced
 * duplicate rows per identifier - those are deduplicated first (keeping the
 * highest id, i.e. the most recently created row) so CREATE UNIQUE INDEX
 * does not fail on existing data.
 */
return new class extends AbstractMigration {
    public function run(): void
    {
        $table = Config::$rateLimitTableName;

        if (!(new Table($table))->exists()) {
            return;
        }

        $pdo = DatabaseManager::$connection->getConnection();
        $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $quote = $driver === 'pgsql' ? '"' : '`';
        $quotedTable = $this->identifier($table, $quote);

        $pdo->exec(
            "DELETE FROM {$quotedTable} WHERE {$this->identifier('id', $quote)} NOT IN ("
            . "SELECT {$this->identifier('max_id', $quote)} FROM ("
            . "SELECT MAX({$this->identifier('id', $quote)}) AS {$this->identifier('max_id', $quote)}"
            . " FROM {$quotedTable} GROUP BY {$this->identifier('identifier', $quote)}"
            . ") AS deduped)"
        );

        $index = $this->identifier('authorization_rate_limit_identifier_unique', $quote);
        $column = $this->identifier('identifier', $quote);
        $pdo->exec("CREATE UNIQUE INDEX {$index} ON {$quotedTable} ({$column})");
    }

    private function identifier(string $identifier, string $quote): string
    {
        $parts = explode('.', $identifier);

        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $part)) {
                throw new InvalidArgumentException('Invalid rate-limit migration identifier');
            }
        }

        return implode('.', array_map(
            static fn(string $part): string => $quote . $part . $quote,
            $parts,
        ));
    }
};
