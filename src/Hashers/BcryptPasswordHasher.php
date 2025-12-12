<?php

namespace NimblePHP\Authorization\Hashers;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

/**
 * BcryptPasswordHasher - Implementation using PHP's password_hash with bcrypt
 * 
 * Bezpieczna implementacja wykorzystująca wbudowaną funkcję PHP `password_hash`
 * z algorytmem bcrypt, który jest odporny na ataki słownikowe.
 * 
 * Konfiguracja:
 * ```php
 * Config::setPasswordHasher(new BcryptPasswordHasher(
 *     cost: 12  // Domyślnie 10, wyższa wartość = bardziej bezpieczne, ale wolniejsze
 * ));
 * ```
 * 
 * @package NimblePHP\Authorization\Hashers
 */
class BcryptPasswordHasher implements PasswordHasher
{
    /**
     * Bcrypt cost parameter (4-31, default 10)
     * @var int
     */
    private int $cost;

    /**
     * Construct BcryptPasswordHasher
     * 
     * @param int $cost Bcrypt cost parameter (default: 12 for better security)
     */
    public function __construct(int $cost = 12)
    {
        if ($cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException('Cost must be between 4 and 31');
        }
        $this->cost = $cost;
    }

    /**
     * Hash a password using bcrypt
     * 
     * @param string $password The plain text password to hash
     * @return string The hashed password
     */
    public function hash(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    /**
     * Verify a password against a bcrypt hash
     * 
     * @param string $hash The stored password hash
     * @param string $password The plain text password to verify
     * @return bool True if password matches hash
     */
    public function verify(string $hash, string $password): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if a hash needs to be rehashed
     * 
     * Returns true if:
     * - Hash algorithm is outdated
     * - Cost parameter needs update
     * 
     * @param string $hash The password hash to check
     * @return bool True if hash should be rehashed
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    /**
     * Set cost parameter
     * 
     * @param int $cost Cost parameter (4-31)
     * @return void
     */
    public function setCost(int $cost): void
    {
        if ($cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException('Cost must be between 4 and 31');
        }
        $this->cost = $cost;
    }

    /**
     * Get cost parameter
     * 
     * @return int
     */
    public function getCost(): int
    {
        return $this->cost;
    }
}
