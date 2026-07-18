<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Services;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use NimblePHP\Authorization\Config;
use PDO;

/**
 * Authoritative account-state and credential-version boundary.
 *
 * Every access path must require an existing active account. The monotonically
 * increasing auth epoch invalidates sessions and tokens issued before a
 * security-sensitive account change.
 */
final class AccountStateService
{
    private PDO $pdo;
    private string $quote;

    public function __construct(?PDO $pdo = null)
    {
        $this->pdo = $pdo ?? DatabaseManager::$connection->getConnection();
        $this->quote = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql' ? '"' : '`';
    }

    /** @return array<string, mixed>|null */
    public function find(int $accountId): ?array
    {
        if ($accountId <= 0) {
            return null;
        }

        $sql = 'SELECT * FROM ' . $this->identifier(Config::$tableName)
            . ' WHERE ' . $this->identifier(Config::getColumn('id')) . ' = :account_id LIMIT 1';
        $statement = $this->pdo->prepare($sql);
        $statement->execute(['account_id' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    /** @return array<string, mixed>|null */
    public function findActive(int $accountId): ?array
    {
        $account = $this->find($accountId);

        if ($account === null || empty($account[Config::getColumn('active')])) {
            return null;
        }

        $epoch = $account[Config::getColumn('auth_epoch')] ?? null;
        if (!$this->isNonNegativeInteger($epoch)) {
            return null;
        }

        return $account;
    }

    /** @param array<string, mixed> $account */
    public function epoch(array $account): int
    {
        $epoch = $account[Config::getColumn('auth_epoch')] ?? null;

        if (!$this->isNonNegativeInteger($epoch)) {
            throw new InvalidArgumentException('Account credential epoch is missing or invalid');
        }

        return (int)$epoch;
    }

    private function isNonNegativeInteger(mixed $value): bool
    {
        return (is_int($value) && $value >= 0)
            || (is_string($value) && ctype_digit($value));
    }

    public function incrementEpoch(int $accountId): bool
    {
        $epoch = $this->identifier(Config::getColumn('auth_epoch'));
        $sql = 'UPDATE ' . $this->identifier(Config::$tableName)
            . " SET {$epoch} = {$epoch} + 1"
            . ' WHERE ' . $this->identifier(Config::getColumn('id')) . ' = :account_id';
        $statement = $this->pdo->prepare($sql);

        return $statement->execute(['account_id' => $accountId]) && $statement->rowCount() === 1;
    }

    public function deactivate(int $accountId): bool
    {
        $epoch = $this->identifier(Config::getColumn('auth_epoch'));
        $sql = 'UPDATE ' . $this->identifier(Config::$tableName)
            . ' SET ' . $this->identifier(Config::getColumn('active')) . ' = 0,'
            . " {$epoch} = {$epoch} + 1"
            . ' WHERE ' . $this->identifier(Config::getColumn('id')) . ' = :account_id';
        $statement = $this->pdo->prepare($sql);

        return $statement->execute(['account_id' => $accountId]) && $statement->rowCount() === 1;
    }

    private function identifier(string $identifier): string
    {
        $parts = explode('.', $identifier);

        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $part)) {
                throw new InvalidArgumentException('Invalid account-state database identifier');
            }
        }

        return implode('.', array_map(fn(string $part): string => $this->quote . $part . $this->quote, $parts));
    }
}
