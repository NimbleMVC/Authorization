<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use NimblePHP\Authorization\Events\RateLimitLockedEvent;
use NimblePHP\Authorization\Interfaces\RateLimiterStorage;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Translation\Translation;

/**
 * RateLimiter class - Protects against brute force attacks using rate limiting
 *
 * This class provides:
 * - Login attempt tracking per identifier (username/email) and optionally per client IP
 * - Configurable attempt limits and lockout duration
 * - Pluggable storage (session by default, database for persistent protection)
 * - Automatic reset after lockout period expires
 *
 * @package NimblePHP\Authorization
 */
class RateLimiter
{

    /**
     * Storage backend
     * @var RateLimiterStorage
     */
    private RateLimiterStorage $storage;

    /**
     * Construct RateLimiter instance
     */
    public function __construct()
    {
        $this->storage = Config::getRateLimiterStorage();
    }

    /**
     * Check if login is rate limited for given identifier (or its client IP)
     *
     * @param string $identifier Username or email
     * @return bool True if rate limited (blocked), false if allowed
     */
    public function isRateLimited(string $identifier): bool
    {
        foreach ($this->getKeys($identifier) as $key) {
            if ($this->isKeyLimited($key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record a failed login attempt (for the identifier and, if enabled, the client IP)
     *
     * @param string $identifier Username or email
     * @return void
     */
    public function recordFailedAttempt(string $identifier): void
    {
        $maxAttempts = Config::getRateLimitMaxAttempts();
        $lockoutDuration = Config::getRateLimitLockoutDuration();
        $now = time();

        foreach ($this->getKeys($identifier) as $key) {
            $data = $this->storage->get($key) ?? [
                'attempts' => 0,
                'first_attempt' => $now,
                'locked_until' => null
            ];

            // Forget stale counters (observation window = lockout duration)
            if (empty($data['locked_until']) && isset($data['last_attempt']) && ($now - (int)$data['last_attempt']) > $lockoutDuration) {
                $data = [
                    'attempts' => 0,
                    'first_attempt' => $now,
                    'locked_until' => null
                ];
            }

            $data['attempts']++;
            $data['last_attempt'] = $now;

            // Check if max attempts exceeded
            $wasLocked = !empty($data['locked_until']);

            if ($data['attempts'] >= $maxAttempts) {
                $data['locked_until'] = $now + $lockoutDuration;
            }

            $this->storage->set($key, $data);

            if (!$wasLocked && !empty($data['locked_until'])) {
                Kernel::dispatchEvent(new RateLimitLockedEvent($key, (int)$data['locked_until']));
            }
        }
    }

    /**
     * Clear rate limit for identifier (successful login)
     *
     * @param string $identifier Username or email
     * @return void
     */
    public function clearAttempts(string $identifier): void
    {
        foreach ($this->getKeys($identifier) as $key) {
            $this->storage->remove($key);
        }
    }

    /**
     * Get remaining attempts before lockout
     *
     * @param string $identifier Username or email
     * @return int Number of attempts remaining (0 if locked)
     */
    public function getRemainingAttempts(string $identifier): int
    {
        if ($this->isRateLimited($identifier)) {
            return 0;
        }

        $remaining = Config::getRateLimitMaxAttempts();

        foreach ($this->getKeys($identifier) as $key) {
            $data = $this->storage->get($key);

            if ($data === null) {
                continue;
            }

            $remaining = min($remaining, Config::getRateLimitMaxAttempts() - (int)$data['attempts']);
        }

        return max(0, $remaining);
    }

    /**
     * Get time remaining in lockout (in seconds)
     *
     * @param string $identifier Username or email
     * @return int Seconds remaining in lockout (0 if not locked)
     */
    public function getLockoutTimeRemaining(string $identifier): int
    {
        $remaining = 0;

        foreach ($this->getKeys($identifier) as $key) {
            $data = $this->storage->get($key);

            if ($data === null || empty($data['locked_until'])) {
                continue;
            }

            $remaining = max($remaining, (int)$data['locked_until'] - time());
        }

        return max(0, $remaining);
    }

    /**
     * Check single tracking key, cleaning up expired lockouts
     *
     * @param string $key
     * @return bool
     */
    private function isKeyLimited(string $key): bool
    {
        $data = $this->storage->get($key);

        if ($data === null) {
            return false;
        }

        $now = time();

        // Check if lockout period has expired
        if (isset($data['locked_until']) && $data['locked_until'] < $now) {
            $this->storage->remove($key);
            return false;
        }

        // Check if currently locked
        return isset($data['locked_until']) && $data['locked_until'] >= $now;
    }

    /**
     * Get tracking keys for identifier (identifier itself + optional client IP)
     *
     * @param string $identifier Username or email
     * @return string[]
     */
    private function getKeys(string $identifier): array
    {
        if (empty(trim($identifier))) {
            throw new InvalidArgumentException(Translation::getInstance()->translate('module.authorization.errors.identifier_empty'));
        }

        $keys = [$identifier];

        if (Config::$rateLimitTrackIp && !empty($_SERVER['REMOTE_ADDR'])) {
            $keys[] = 'ip:' . $_SERVER['REMOTE_ADDR'];
        }

        return $keys;
    }

    /**
     * Reset all rate limits (admin function)
     *
     * @return void
     */
    public function resetAll(): void
    {
        $this->storage->removeAll();
    }
}
