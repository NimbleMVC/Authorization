<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Storages;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\RecoveryCodeStorage;
use PDO;
use Throwable;

final class DatabaseRecoveryCodeStorage implements RecoveryCodeStorage
{
    private PDO $pdo;

    private string $tableName;

    private string $quotedTableName;

    public function __construct(?PDO $pdo = null, ?string $tableName = null)
    {
        $this->pdo = $pdo ?? DatabaseManager::$connection->getConnection();
        $this->tableName = $tableName ?? Config::$recoveryCodeTableName;

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $this->tableName) !== 1) {
            throw new InvalidArgumentException('Invalid recovery-code table name');
        }

        $quote = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql' ? '"' : '`';
        $this->quotedTableName = $quote . $this->tableName . $quote;
    }

    public function replaceForAccount(int $accountId, array $codes): void
    {
        $startedTransaction = !$this->pdo->inTransaction();

        try {
            if ($startedTransaction) {
                $this->pdo->beginTransaction();
            }

            $delete = $this->pdo->prepare(
                'DELETE FROM ' . $this->quotedTableName . ' WHERE account_id = :account_id'
            );
            $delete->execute(['account_id' => $accountId]);

            $insert = $this->pdo->prepare(
                'INSERT INTO ' . $this->quotedTableName
                . ' (account_id, code_hash, expires_at)'
                . ' VALUES (:account_id, :code_hash, :expires_at)'
            );

            foreach ($codes as $code) {
                $insert->execute([
                    'account_id' => $accountId,
                    'code_hash' => $code['code_hash'],
                    'expires_at' => $code['expires_at'],
                ]);
            }

            if ($startedTransaction) {
                $this->pdo->commit();
            }
        } catch (Throwable $exception) {
            if ($startedTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            throw new DatabaseManagerException($exception->getMessage(), (int)$exception->getCode(), $exception);
        }
    }

    public function findActiveForAccount(int $accountId, string $now): array
    {
        try {
            $statement = $this->pdo->prepare(
                'SELECT id, code_hash FROM ' . $this->quotedTableName
                . ' WHERE account_id = :account_id'
                . ' AND used_at IS NULL AND expires_at > :now'
            );
            $statement->execute([
                'account_id' => $accountId,
                'now' => $now,
            ]);

            return $statement->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $exception) {
            throw new DatabaseManagerException($exception->getMessage(), (int)$exception->getCode(), $exception);
        }
    }

    public function consume(int $id, int $accountId, string $usedAt): bool
    {
        try {
            $statement = $this->pdo->prepare(
                'UPDATE ' . $this->quotedTableName
                . ' SET used_at = :used_at, date_modify = :date_modify'
                . ' WHERE id = :id AND account_id = :account_id'
                . ' AND used_at IS NULL AND expires_at > :expires_after'
            );
            $statement->execute([
                'used_at' => $usedAt,
                'date_modify' => $usedAt,
                'expires_after' => $usedAt,
                'id' => $id,
                'account_id' => $accountId,
            ]);

            return $statement->rowCount() === 1;
        } catch (Throwable $exception) {
            throw new DatabaseManagerException($exception->getMessage(), (int)$exception->getCode(), $exception);
        }
    }

    public function deleteForAccount(int $accountId): void
    {
        try {
            $statement = $this->pdo->prepare(
                'DELETE FROM ' . $this->quotedTableName . ' WHERE account_id = :account_id'
            );
            $statement->execute(['account_id' => $accountId]);
        } catch (Throwable $exception) {
            throw new DatabaseManagerException($exception->getMessage(), (int)$exception->getCode(), $exception);
        }
    }
}
