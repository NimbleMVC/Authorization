<?php

namespace NimblePHP\Authorization\Services;

use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Events\RememberTokenCreatedEvent;
use NimblePHP\Authorization\Events\RememberTokenTheftDetectedEvent;
use NimblePHP\Authorization\Events\RememberTokenUsedEvent;
use NimblePHP\Framework\Kernel;
use PDO;

/**
 * RememberMeService - Persistent "remember me" login tokens
 *
 * Selector/validator scheme: the cookie holds "selector:validator", the
 * database stores the selector and a sha256 hash of the validator. Token is
 * rotated periodically (Config::$rememberMeRotationInterval) on successful
 * use. A valid selector with a wrong validator is treated as token theft -
 * all tokens of that account are invalidated.
 *
 * Rotation consumes the old row atomically (AUT-M05: a conditional UPDATE
 * setting used_at, checked via rowCount(), instead of a read-then-delete
 * race two concurrent requests could both win) and every token issued
 * through one continuous chain of rotations shares a family_id. A validator
 * match against a token whose used_at is already set - a stale, already-
 * rotated-away token being replayed, or a request that lost the atomic
 * consume race in the same instant - is treated as reuse (theft) the same
 * way a wrong validator is: this is the standard, deliberately
 * false-positive-tolerant stance rotation schemes use (e.g. OAuth2 refresh
 * token rotation), and the rotation throttle below already keeps the
 * window an honest race could land in narrow.
 *
 * Enable via:
 * ```
 * AUTHORIZATION_REMEMBER_ME_ENABLED=true
 * ```
 *
 * @package NimblePHP\Authorization\Services
 */
class RememberMeService
{

    /**
     * Create a remember-me token for account and set the cookie
     * @param int $accountId
     * @param string|null $familyId Continue an existing rotation chain (internal use by check()); null starts a new one
     * @return void
     */
    public function create(int $accountId, ?string $familyId = null): void
    {
        $selector = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(32));
        $tableName = Config::$rememberMeTableName;
        $familyId ??= bin2hex(random_bytes(16));

        $expiresAt = date('Y-m-d H:i:s', time() + Config::$rememberMeLifetime);

        (new Table($tableName))->insert([
            'account_id' => $accountId,
            'selector' => $selector,
            'validator_hash' => hash('sha256', $validator),
            'family_id' => $familyId,
            'date_expired' => $expiresAt
        ]);

        $this->setCookie($selector . ':' . $validator, time() + Config::$rememberMeLifetime);
        Kernel::dispatchEvent(new RememberTokenCreatedEvent($accountId, $selector, $expiresAt));
    }

    /**
     * Validate the remember-me cookie and rotate the token on success
     * @return int|null Account id or null when the cookie is missing/invalid
     */
    public function check(): ?int
    {
        $cookie = $_COOKIE[Config::$rememberMeCookieName] ?? '';

        if (!is_string($cookie) || !str_contains($cookie, ':')) {
            return null;
        }

        [$selector, $validator] = explode(':', $cookie, 2);

        if ($selector === '' || $validator === '') {
            $this->clearCookie();

            return null;
        }

        $tableName = Config::$rememberMeTableName;
        $table = new Table($tableName);
        $row = $table->find([$tableName . '.selector' => $selector]);

        if (empty($row)) {
            $this->clearCookie();

            return null;
        }

        $token = $row[$tableName];
        $accountId = (int)$token['account_id'];

        if (!hash_equals($token['validator_hash'], hash('sha256', $validator))) {
            // Valid selector with wrong validator - possible token theft
            $this->invalidateAll($accountId);
            $this->clearCookie();
            Kernel::dispatchEvent(new RememberTokenTheftDetectedEvent($accountId));

            return null;
        }

        if (strtotime($token['date_expired']) < time()) {
            $table->delete((int)$token['id']);
            $this->clearCookie();

            return null;
        }

        // AUT-M05: a validator match against a token already consumed by an
        // earlier rotation is reuse - the legitimate chain has already moved
        // past this selector. Treated the same as a wrong validator.
        if (!empty($token['used_at'])) {
            $this->invalidateAll($accountId);
            $this->clearCookie();
            Kernel::dispatchEvent(new RememberTokenTheftDetectedEvent($accountId));

            return null;
        }

        Kernel::dispatchEvent(new RememberTokenUsedEvent($accountId, $selector));

        // Rotating on every use races: concurrent requests from the same
        // page load (assets/AJAX) carry the same not-yet-rotated cookie, the
        // first one to be processed rotates it, and every other concurrent
        // request then finds the selector already deleted and clears the
        // user's cookie - a real logout well before the token's lifetime.
        // Throttle rotation instead of skipping it: a token still gets
        // replaced periodically (theft-detection keeps working), but a
        // realistic burst of concurrent requests shares the same token.
        $ageSeconds = time() - strtotime((string)($token['date_created'] ?? 'now'));

        if ($ageSeconds < Config::$rememberMeRotationInterval) {
            return $accountId;
        }

        // AUT-M05: consume this token atomically (single conditional UPDATE,
        // rowCount() is the proof of success) instead of the previous
        // read-then-delete pair two concurrent requests could both pass.
        if (!$this->consume((int)$token['id'])) {
            // Someone else won the consume race in this same instant. Since
            // used_at was NULL a moment ago in our own read above, this can
            // only be an honest race, not a stale replay - but we cannot
            // hand this request the winner's new plaintext validator either
            // (only the winning process ever holds it), so there is no safe
            // token to keep serving. Fail the same way genuine reuse does.
            $this->invalidateAll($accountId);
            $this->clearCookie();
            Kernel::dispatchEvent(new RememberTokenTheftDetectedEvent($accountId));

            return null;
        }

        $this->create($accountId, is_string($token['family_id'] ?? null) ? $token['family_id'] : null);

        return $accountId;
    }

    /**
     * Atomically mark a token row consumed (AUT-M05). Returns true only for
     * the single caller that flips used_at from NULL - a concurrent racer
     * calling this for the same id gets false.
     *
     * @param int $id
     * @return bool
     */
    private function consume(int $id): bool
    {
        $pdo = DatabaseManager::$connection->getConnection();
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $quote = $driver === 'pgsql' ? '"' : '`';
        $table = $quote . Config::$rememberMeTableName . $quote;

        $statement = $pdo->prepare(
            "UPDATE {$table} SET {$quote}used_at{$quote} = :used_at"
            . " WHERE {$quote}id{$quote} = :id AND {$quote}used_at{$quote} IS NULL"
        );
        $statement->bindValue('used_at', date('Y-m-d H:i:s'), PDO::PARAM_STR);
        $statement->bindValue('id', $id, PDO::PARAM_INT);
        $statement->execute();

        return $statement->rowCount() === 1;
    }

    /**
     * Remove the token behind the current cookie and clear the cookie
     * @return void
     */
    public function forget(): void
    {
        $cookie = $_COOKIE[Config::$rememberMeCookieName] ?? '';

        if (is_string($cookie) && str_contains($cookie, ':')) {
            [$selector] = explode(':', $cookie, 2);

            if ($selector !== '') {
                $tableName = Config::$rememberMeTableName;
                (new Table($tableName))->deleteByConditions([$tableName . '.selector' => $selector]);
            }
        }

        $this->clearCookie();
    }

    /**
     * Invalidate all remember-me tokens of an account (e.g. on password change)
     * @param int $accountId
     * @return void
     */
    public function invalidateAll(int $accountId): void
    {
        $tableName = Config::$rememberMeTableName;
        (new Table($tableName))->deleteByConditions([$tableName . '.account_id' => $accountId]);
    }

    /**
     * @param string $value
     * @param int $expires
     * @return void
     */
    private function setCookie(string $value, int $expires): void
    {
        setcookie(Config::$rememberMeCookieName, $value, [
            'expires' => $expires,
            'path' => '/',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    /**
     * @return void
     */
    private function clearCookie(): void
    {
        unset($_COOKIE[Config::$rememberMeCookieName]);
        $this->setCookie('', time() - 3600);
    }

}
