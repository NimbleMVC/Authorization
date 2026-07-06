<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * RateLimiterStorage Interface - Persistence backend for login rate limiting
 *
 * Implementations store attempt counters per identifier (username, email
 * or "ip:<address>"). The default session storage only tracks the current
 * browser session; use the database storage for real brute-force protection.
 *
 * @package NimblePHP\Authorization\Interfaces
 */
interface RateLimiterStorage
{

    /**
     * Get rate limit data for identifier
     * @param string $identifier
     * @return array|null Array with keys: attempts, first_attempt, last_attempt, locked_until - or null
     */
    public function get(string $identifier): ?array;

    /**
     * Store rate limit data for identifier
     * @param string $identifier
     * @param array $data Array with keys: attempts, first_attempt, last_attempt, locked_until
     * @return void
     */
    public function set(string $identifier, array $data): void;

    /**
     * Remove rate limit data for identifier
     * @param string $identifier
     * @return void
     */
    public function remove(string $identifier): void;

    /**
     * Remove all rate limit data (admin function)
     * @return void
     */
    public function removeAll(): void;

}
