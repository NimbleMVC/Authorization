<?php

namespace NimblePHP\Authorization\Storages;

use NimblePHP\Authorization\Interfaces\RateLimiterStorage;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;

/**
 * SessionRateLimiterStorage - Keeps counters in the session
 *
 * Preserves the historical behaviour of the module (keys rate_limit_<md5>).
 * Only protects within a single browser session - an attacker dropping the
 * cookie resets the counters. Used as the default only when the database
 * table is unavailable or when forced via AUTHORIZATION_RATE_LIMIT_STORAGE=session.
 *
 * @package NimblePHP\Authorization\Storages
 */
class SessionRateLimiterStorage implements RateLimiterStorage
{

    /**
     * Session key prefix for rate limiting
     * @var string
     */
    private string $sessionKeyPrefix = 'rate_limit_';

    /**
     * Session instance
     * @var Session
     */
    private Session $session;

    public function __construct()
    {
        $this->session = Kernel::$serviceContainer->get('kernel.session');
    }

    /**
     * @param string $identifier
     * @return array|null
     */
    public function get(string $identifier): ?array
    {
        $key = $this->getSessionKey($identifier);

        return $this->session->exists($key) ? $this->session->get($key) : null;
    }

    /**
     * @param string $identifier
     * @param array $data
     * @return void
     */
    public function set(string $identifier, array $data): void
    {
        $this->session->set($this->getSessionKey($identifier), $data);
    }

    /**
     * @param string $identifier
     * @return void
     */
    public function remove(string $identifier): void
    {
        $this->session->remove($this->getSessionKey($identifier));
    }

    /**
     * @return void
     */
    public function removeAll(): void
    {
        foreach (array_keys($this->session->getAll()) as $key) {
            if (str_starts_with($key, $this->sessionKeyPrefix)) {
                $this->session->remove($key);
            }
        }
    }

    /**
     * @param string $identifier
     * @return string
     */
    private function getSessionKey(string $identifier): string
    {
        return $this->sessionKeyPrefix . md5($identifier);
    }

}
