<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;

/**
 * RateLimiter class - Protects against brute force attacks using rate limiting
 * 
 * This class provides:
 * - Login attempt tracking per user/IP
 * - Configurable attempt limits and lockout duration
 * - Session-based and time-based blocking
 * - Automatic reset after lockout period expires
 * 
 * @package NimblePHP\Authorization
 */
class RateLimiter
{
    /**
     * Session instance
     * @var Session
     */
    private Session $session;

    /**
     * Session key prefix for rate limiting
     * @var string
     */
    private string $sessionKeyPrefix = 'rate_limit_';

    /**
     * Construct RateLimiter instance
     */
    public function __construct()
    {
        $this->session = Kernel::$serviceContainer->get('kernel.session');
    }

    /**
     * Check if login is rate limited for given identifier
     * 
     * @param string $identifier Username or email
     * @return bool True if rate limited (blocked), false if allowed
     */
    public function isRateLimited(string $identifier): bool
    {
        $key = $this->getSessionKey($identifier);
        
        if (!$this->session->exists($key)) {
            return false;
        }

        $data = $this->session->get($key);
        $now = time();

        // Check if lockout period has expired
        if (isset($data['locked_until']) && $data['locked_until'] < $now) {
            $this->session->remove($key);
            return false;
        }

        // Check if currently locked
        return isset($data['locked_until']) && $data['locked_until'] >= $now;
    }

    /**
     * Record a failed login attempt
     * 
     * @param string $identifier Username or email
     * @return void
     */
    public function recordFailedAttempt(string $identifier): void
    {
        $key = $this->getSessionKey($identifier);
        $maxAttempts = Config::getRateLimitMaxAttempts();
        $lockoutDuration = Config::getRateLimitLockoutDuration();
        $now = time();

        $data = $this->session->exists($key) ? $this->session->get($key) : [
            'attempts' => 0,
            'first_attempt' => $now,
            'locked_until' => null
        ];

        $data['attempts']++;
        $data['last_attempt'] = $now;

        // Check if max attempts exceeded
        if ($data['attempts'] >= $maxAttempts) {
            $data['locked_until'] = $now + $lockoutDuration;
        }

        $this->session->set($key, $data);
    }

    /**
     * Clear rate limit for identifier (successful login)
     * 
     * @param string $identifier Username or email
     * @return void
     */
    public function clearAttempts(string $identifier): void
    {
        $key = $this->getSessionKey($identifier);
        $this->session->remove($key);
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

        $key = $this->getSessionKey($identifier);
        
        if (!$this->session->exists($key)) {
            return Config::getRateLimitMaxAttempts();
        }

        $data = $this->session->get($key);
        $remaining = Config::getRateLimitMaxAttempts() - $data['attempts'];

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
        if (!$this->isRateLimited($identifier)) {
            return 0;
        }

        $key = $this->getSessionKey($identifier);
        $data = $this->session->get($key);
        $remaining = $data['locked_until'] - time();

        return max(0, $remaining);
    }

    /**
     * Get session key for rate limit tracking
     * 
     * @param string $identifier Username or email
     * @return string Session key
     */
    private function getSessionKey(string $identifier): string
    {
        if (empty(trim($identifier))) {
            throw new InvalidArgumentException('Identifier cannot be empty');
        }

        return $this->sessionKeyPrefix . md5($identifier);
    }

    /**
     * Reset all rate limits (admin function)
     * 
     * @return void
     */
    public function resetAll(): void
    {
        $session = Kernel::$serviceContainer->get('kernel.session');
        $sessionData = $session->getAll();

        foreach (array_keys($sessionData) as $key) {
            if (strpos($key, $this->sessionKeyPrefix) === 0) {
                $session->remove($key);
            }
        }
    }
}
