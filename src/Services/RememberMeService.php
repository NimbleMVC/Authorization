<?php

namespace NimblePHP\Authorization\Services;

use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Events\RememberTokenCreatedEvent;
use NimblePHP\Authorization\Events\RememberTokenTheftDetectedEvent;
use NimblePHP\Authorization\Events\RememberTokenUsedEvent;
use NimblePHP\Framework\Kernel;

/**
 * RememberMeService - Persistent "remember me" login tokens
 *
 * Selector/validator scheme: the cookie holds "selector:validator", the
 * database stores the selector and a sha256 hash of the validator. Token is
 * rotated on every successful use. A valid selector with a wrong validator
 * is treated as token theft - all tokens of that account are invalidated.
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
     * @return void
     */
    public function create(int $accountId): void
    {
        $selector = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(32));
        $tableName = Config::$rememberMeTableName;

        $expiresAt = date('Y-m-d H:i:s', time() + Config::$rememberMeLifetime);

        (new Table($tableName))->insert([
            'account_id' => $accountId,
            'selector' => $selector,
            'validator_hash' => hash('sha256', $validator),
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

        // Rotate: single-use token
        $table->delete((int)$token['id']);
        $this->create($accountId);

        return $accountId;
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
