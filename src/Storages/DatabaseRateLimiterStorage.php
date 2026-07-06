<?php

namespace NimblePHP\Authorization\Storages;

use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\RateLimiterStorage;
use NimblePHP\Framework\Log;
use Throwable;

/**
 * DatabaseRateLimiterStorage - Persistent storage for login rate limiting (default)
 *
 * Counters survive session drops, which makes lockouts effective against
 * real brute-force attacks (per identifier and - with
 * AUTHORIZATION_RATE_LIMIT_TRACK_IP - per client IP).
 *
 * When the rate limit table does not exist (e.g. AUTHORIZATION_MANAGE_SCHEMA=false
 * without creating the table), the storage logs a warning once and falls back
 * to SessionRateLimiterStorage so logins keep working.
 *
 * Force the session backend via:
 * ```
 * AUTHORIZATION_RATE_LIMIT_STORAGE=session
 * ```
 *
 * @package NimblePHP\Authorization\Storages
 */
class DatabaseRateLimiterStorage implements RateLimiterStorage
{

    /**
     * Fallback storage after a missing-table error (per request)
     * @var SessionRateLimiterStorage|null
     */
    private static ?SessionRateLimiterStorage $fallback = null;

    /**
     * @param string $identifier
     * @return array|null
     */
    public function get(string $identifier): ?array
    {
        if (self::$fallback !== null) {
            return self::$fallback->get($identifier);
        }

        try {
            $tableName = Config::$rateLimitTableName;
            $row = (new Table($tableName))->find([$tableName . '.identifier' => $this->hashIdentifier($identifier)]);
        } catch (Throwable $exception) {
            $this->handleMissingTable($exception);

            return self::$fallback->get($identifier);
        }

        if (empty($row)) {
            return null;
        }

        $data = $row[$tableName];

        return [
            'attempts' => (int)$data['attempts'],
            'first_attempt' => (int)$data['first_attempt'],
            'last_attempt' => (int)$data['last_attempt'],
            'locked_until' => $data['locked_until'] !== null ? (int)$data['locked_until'] : null
        ];
    }

    /**
     * @param string $identifier
     * @param array $data
     * @return void
     */
    public function set(string $identifier, array $data): void
    {
        if (self::$fallback !== null) {
            self::$fallback->set($identifier, $data);

            return;
        }

        try {
            $tableName = Config::$rateLimitTableName;
            $table = new Table($tableName);
            $hashedIdentifier = $this->hashIdentifier($identifier);
            $row = $table->find([$tableName . '.identifier' => $hashedIdentifier], [$tableName . '.id']);
            $values = [
                'attempts' => (int)($data['attempts'] ?? 0),
                'first_attempt' => (int)($data['first_attempt'] ?? time()),
                'last_attempt' => (int)($data['last_attempt'] ?? time()),
                'locked_until' => isset($data['locked_until']) ? (int)$data['locked_until'] : null
            ];

            if (empty($row)) {
                $table->insert(array_merge(['identifier' => $hashedIdentifier], $values));
            } else {
                $table->setId((int)$row[$tableName]['id'])->update($values);
            }
        } catch (Throwable $exception) {
            $this->handleMissingTable($exception);
            self::$fallback->set($identifier, $data);
        }
    }

    /**
     * @param string $identifier
     * @return void
     */
    public function remove(string $identifier): void
    {
        if (self::$fallback !== null) {
            self::$fallback->remove($identifier);

            return;
        }

        try {
            $tableName = Config::$rateLimitTableName;
            (new Table($tableName))->deleteByConditions([$tableName . '.identifier' => $this->hashIdentifier($identifier)]);
        } catch (Throwable $exception) {
            $this->handleMissingTable($exception);
            self::$fallback->remove($identifier);
        }
    }

    /**
     * @return void
     */
    public function removeAll(): void
    {
        if (self::$fallback !== null) {
            self::$fallback->removeAll();

            return;
        }

        try {
            $tableName = Config::$rateLimitTableName;
            (new Table($tableName))->query('DELETE FROM `' . $tableName . '`');
        } catch (Throwable $exception) {
            $this->handleMissingTable($exception);
            self::$fallback->removeAll();
        }
    }

    /**
     * Switch to the session fallback on a missing-table error, rethrow anything else
     * @param Throwable $exception
     * @return void
     * @throws Throwable
     */
    private function handleMissingTable(Throwable $exception): void
    {
        $message = strtolower($exception->getMessage());

        if (!str_contains($message, 'base table or view not found') && !str_contains($message, '42s02')) {
            throw $exception;
        }

        Log::log(
            'Rate limit table missing, falling back to session storage - create the table (module migrations) or set AUTHORIZATION_RATE_LIMIT_STORAGE=session',
            'WARNING',
            ['table' => Config::$rateLimitTableName]
        );

        self::$fallback = new SessionRateLimiterStorage();
    }

    /**
     * Hash identifier before storing (no plaintext emails/IPs in the table)
     * @param string $identifier
     * @return string
     */
    private function hashIdentifier(string $identifier): string
    {
        return hash('sha256', mb_strtolower(trim($identifier)));
    }

}
