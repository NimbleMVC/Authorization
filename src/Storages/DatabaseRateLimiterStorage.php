<?php

namespace NimblePHP\Authorization\Storages;

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\RateLimiterStorage;
use NimblePHP\Framework\Log;
use PDO;
use Throwable;

/**
 * DatabaseRateLimiterStorage - Persistent storage for login rate limiting (default)
 *
 * Counters survive session drops, which makes lockouts effective against
 * real brute-force attacks (per identifier and - with
 * AUTHORIZATION_RATE_LIMIT_TRACK_IP - per client IP). increment() applies
 * the attempt counter atomically via a portable UPSERT (AUT-M04), so
 * concurrent requests cannot race past the configured attempt limit.
 *
 * When the rate limit table does not exist (e.g. AUTHORIZATION_MANAGE_SCHEMA=false
 * without creating the table), the storage fails closed by default (throws)
 * instead of silently degrading brute-force protection. Opt into the old,
 * weaker session-backed fallback explicitly via
 * AUTHORIZATION_RATE_LIMIT_ALLOW_SESSION_FALLBACK=true.
 *
 * Force the session backend outright via:
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
     * Atomically increment attempts for identifier (AUT-M04).
     *
     * A single portable UPSERT applies the stale-window reset, the
     * increment, and the locked_until threshold together, so concurrent
     * callers cannot race a separate get()-then-set() past $maxAttempts.
     * Requires the unique index on `identifier` added by migration 1787209000.
     *
     * @param string $identifier
     * @param int $now
     * @param int $maxAttempts
     * @param int $lockoutDuration
     * @return array
     */
    public function increment(string $identifier, int $now, int $maxAttempts, int $lockoutDuration): array
    {
        if (self::$fallback !== null) {
            return self::$fallback->increment($identifier, $now, $maxAttempts, $lockoutDuration);
        }

        try {
            $tableName = Config::$rateLimitTableName;
            $pdo = DatabaseManager::$connection->getConnection();
            $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $quote = $driver === 'pgsql' ? '"' : '`';
            $table = $quote . $tableName . $quote;

            $windowExpired = static fn(string $suffix): string => "({$quote}last_attempt{$quote} <= :stale_before_{$suffix}"
                . " AND ({$quote}locked_until{$quote} IS NULL OR {$quote}locked_until{$quote} < :now_{$suffix}))";

            $attemptsExpr = "CASE WHEN {$windowExpired('a')} THEN 1 ELSE {$quote}attempts{$quote} + 1 END";
            $firstAttemptExpr = "CASE WHEN {$windowExpired('b')} THEN :reset_first_attempt ELSE {$quote}first_attempt{$quote} END";
            $lockedUntilExpr = "CASE"
                . " WHEN {$quote}locked_until{$quote} IS NOT NULL AND {$quote}locked_until{$quote} >= :now_c THEN {$quote}locked_until{$quote}"
                . " WHEN (CASE WHEN {$windowExpired('d')} THEN 1 ELSE {$quote}attempts{$quote} + 1 END) >= :max_attempts THEN :locked_until_value"
                . " ELSE NULL"
                . " END";

            $setClause = "{$quote}attempts{$quote} = {$attemptsExpr},"
                . " {$quote}first_attempt{$quote} = {$firstAttemptExpr},"
                . " {$quote}last_attempt{$quote} = :now_last,"
                . " {$quote}locked_until{$quote} = {$lockedUntilExpr}";

            $upsert = $driver === 'mysql'
                ? "ON DUPLICATE KEY UPDATE {$setClause}"
                : "ON CONFLICT({$quote}identifier{$quote}) DO UPDATE SET {$setClause}";

            $sql = "INSERT INTO {$table}"
                . " ({$quote}identifier{$quote}, {$quote}attempts{$quote}, {$quote}first_attempt{$quote}, {$quote}last_attempt{$quote}, {$quote}locked_until{$quote})"
                . " VALUES (:identifier, 1, :insert_first, :insert_last, NULL)"
                . " {$upsert}";

            $statement = $pdo->prepare($sql);
            $statement->bindValue('identifier', $this->hashIdentifier($identifier), PDO::PARAM_STR);

            // PDO defaults to PARAM_STR for a plain execute(array) call. SQLite compares
            // by storage class when neither side of an expression is a table column (as
            // with the CASE result compared against :max_attempts below), and INTEGER
            // storage class always sorts below TEXT - so an unbound-type "2 >= '2'" is
            // silently false. Bind every numeric parameter as PARAM_INT to avoid that.
            foreach ([
                'insert_first' => $now,
                'insert_last' => $now,
                'reset_first_attempt' => $now,
                'stale_before_a' => $now - $lockoutDuration,
                'now_a' => $now,
                'stale_before_b' => $now - $lockoutDuration,
                'now_b' => $now,
                'now_c' => $now,
                'stale_before_d' => $now - $lockoutDuration,
                'now_d' => $now,
                'max_attempts' => $maxAttempts,
                'locked_until_value' => $now + $lockoutDuration,
                'now_last' => $now,
            ] as $name => $value) {
                $statement->bindValue($name, $value, PDO::PARAM_INT);
            }

            $statement->execute();
        } catch (Throwable $exception) {
            $this->handleMissingTable($exception);

            return self::$fallback->increment($identifier, $now, $maxAttempts, $lockoutDuration);
        }

        return $this->get($identifier) ?? [
            'attempts' => 1,
            'first_attempt' => $now,
            'last_attempt' => $now,
            'locked_until' => null,
        ];
    }

    /**
     * Fail closed on a missing table by default (AUT-M04): silently
     * downgrading brute-force protection to a per-cookie session counter is
     * itself a security regression an attacker can reset at will. Opt into
     * the old fallback behaviour explicitly via
     * Config::$rateLimitAllowSessionFallback if that degradation is
     * acceptable for this environment.
     *
     * @param Throwable $exception
     * @return void
     * @throws Throwable
     */
    private function handleMissingTable(Throwable $exception): void
    {
        $message = strtolower($exception->getMessage());
        $isMissingTable = str_contains($message, 'base table or view not found') // MySQL
            || str_contains($message, '42s02') // MySQL SQLSTATE
            || str_contains($message, 'no such table') // SQLite
            || str_contains($message, '42p01'); // PostgreSQL SQLSTATE (undefined_table)

        if (!$isMissingTable) {
            throw $exception;
        }

        if (!Config::$rateLimitAllowSessionFallback) {
            throw new DatabaseManagerException(
                'Rate limit table missing - refusing to silently downgrade brute-force protection to '
                . 'session storage. Create the table (module migrations), or set '
                . 'Config::$rateLimitAllowSessionFallback / AUTHORIZATION_RATE_LIMIT_ALLOW_SESSION_FALLBACK=true '
                . 'to explicitly accept the weaker fallback.',
                (int)$exception->getCode(),
                $exception
            );
        }

        Log::log(
            'Rate limit table missing, falling back to session storage '
            . '(AUTHORIZATION_RATE_LIMIT_ALLOW_SESSION_FALLBACK=true) - create the table (module migrations) '
            . 'to restore persistent brute-force protection',
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
