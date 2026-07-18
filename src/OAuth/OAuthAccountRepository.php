<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\OAuth;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use NimblePHP\Authorization\Config;
use PDO;
use RuntimeException;

/**
 * Persistence boundary for OAuth identities.
 *
 * All table and column names come from Config; identity values are always bound
 * parameters. Accounts are addressed by the composite provider/subject key.
 */
final class OAuthAccountRepository
{
    private PDO $pdo;
    private string $quote;

    public function __construct(?PDO $pdo = null)
    {
        $this->pdo = $pdo ?? DatabaseManager::$connection->getConnection();
        $this->quote = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql' ? '"' : '`';
    }

    /** @return array<string, mixed>|null */
    public function findByIdentity(OAuthIdentity $identity): ?array
    {
        return $this->findOne([
            Config::getOAuthColumn('provider') => $identity->provider,
            Config::getOAuthColumn('id') => $identity->subject,
        ]);
    }

    /** @return array<string, mixed>|null */
    public function findByEmail(string $email): ?array
    {
        if ($email === '') {
            return null;
        }

        return $this->findOne([Config::getColumn('email') => $email]);
    }

    /** @return array<string, mixed>|null */
    public function findById(int $accountId): ?array
    {
        return $this->findOne([Config::getColumn('id') => $accountId]);
    }

    /** @return array<string, mixed> */
    public function create(OAuthIdentity $identity): array
    {
        $data = [
            Config::getColumn('username') => $identity->username,
            Config::getColumn('email') => $identity->email,
            Config::getColumn('password') => Config::getPasswordHasher()->hash(bin2hex(random_bytes(32))),
            Config::getColumn('active') => 1,
            Config::getColumn('created_at') => date('Y-m-d H:i:s'),
            Config::getOAuthColumn('id') => $identity->subject,
            Config::getOAuthColumn('provider') => $identity->provider,
        ];

        $columns = array_keys($data);
        $placeholders = array_map(static fn(string $column): string => ':' . $column, $columns);
        $sql = 'INSERT INTO ' . $this->identifier(Config::$tableName)
            . ' (' . implode(', ', array_map($this->identifier(...), $columns)) . ')'
            . ' VALUES (' . implode(', ', $placeholders) . ')';
        $statement = $this->pdo->prepare($sql);

        if (!$statement->execute($data)) {
            throw new RuntimeException('Failed to create OAuth account');
        }

        return $this->findByIdentity($identity)
            ?? throw new RuntimeException('Created OAuth account could not be loaded');
    }

    public function link(int $accountId, OAuthIdentity $identity): bool
    {
        $sql = 'UPDATE ' . $this->identifier(Config::$tableName)
            . ' SET ' . $this->identifier(Config::getOAuthColumn('provider')) . ' = :provider,'
            . ' ' . $this->identifier(Config::getOAuthColumn('id')) . ' = :subject'
            . ' WHERE ' . $this->identifier(Config::getColumn('id')) . ' = :account_id';
        $statement = $this->pdo->prepare($sql);

        return $statement->execute([
            'provider' => $identity->provider,
            'subject' => $identity->subject,
            'account_id' => $accountId,
        ]) && $statement->rowCount() === 1;
    }

    /** @param array<string, scalar> $conditions @return array<string, mixed>|null */
    private function findOne(array $conditions): ?array
    {
        $where = [];
        $values = [];
        $index = 0;

        foreach ($conditions as $column => $value) {
            $parameter = 'condition_' . $index++;
            $where[] = $this->identifier($column) . ' = :' . $parameter;
            $values[$parameter] = $value;
        }

        $sql = 'SELECT * FROM ' . $this->identifier(Config::$tableName)
            . ' WHERE ' . implode(' AND ', $where) . ' LIMIT 1';
        $statement = $this->pdo->prepare($sql);
        $statement->execute($values);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function identifier(string $identifier): string
    {
        $parts = explode('.', $identifier);

        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $part)) {
                throw new InvalidArgumentException('Invalid OAuth database identifier');
            }
        }

        return implode('.', array_map(fn(string $part): string => $this->quote . $part . $this->quote, $parts));
    }
}
