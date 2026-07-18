<?php

declare(strict_types=1);

use krzysztofzylka\DatabaseManager\DatabaseManager;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/** Enforce the OAuth identity invariant at the database boundary. */
return new class extends AbstractMigration {
    public function run(): void
    {
        $pdo = DatabaseManager::$connection->getConnection();
        $quote = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'pgsql' ? '"' : '`';
        $table = $this->identifier(Config::$tableName, $quote);
        $provider = $this->identifier(Config::getOAuthColumn('provider'), $quote);
        $subject = $this->identifier(Config::getOAuthColumn('id'), $quote);
        $index = $this->identifier('authorization_oauth_provider_subject_unique', $quote);

        $pdo->exec("CREATE UNIQUE INDEX {$index} ON {$table} ({$provider}, {$subject})");
    }

    private function identifier(string $identifier, string $quote): string
    {
        $parts = explode('.', $identifier);

        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $part)) {
                throw new InvalidArgumentException('Invalid OAuth migration identifier');
            }
        }

        return implode('.', array_map(
            static fn(string $part): string => $quote . $part . $quote,
            $parts,
        ));
    }
};
