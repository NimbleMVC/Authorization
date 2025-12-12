<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * PasswordHasher Interface - Custom password hashing implementation
 * 
 * Pozwala na implementację własnego algorytmu szyfrowania hasła.
 * 
 * Przykład użycia:
 * ```php
 * class MyCustomHasher implements PasswordHasher {
 *     public function hash(string $password): string {
 *         return hash('sha256', $password);
 *     }
 *     
 *     public function verify(string $hash, string $password): bool {
 *         return hash('sha256', $password) === $hash;
 *     }
 *     
 *     public function needsRehash(string $hash): bool {
 *         return false;
 *     }
 * }
 * 
 * Config::setPasswordHasher(new MyCustomHasher());
 * ```
 * 
 * @package NimblePHP\Authorization\Interfaces
 */
interface PasswordHasher
{
    /**
     * Hash a password
     * 
     * @param string $password The plain text password to hash
     * @return string The hashed password
     */
    public function hash(string $password): string;

    /**
     * Verify a password against a hash
     * 
     * @param string $hash The stored password hash
     * @param string $password The plain text password to verify
     * @return bool True if password matches hash, false otherwise
     */
    public function verify(string $hash, string $password): bool;

    /**
     * Check if a hash needs to be rehashed
     * 
     * Útil when upgrading to a stronger hashing algorithm
     * 
     * @param string $hash The password hash to check
     * @return bool True if hash should be rehashed, false otherwise
     */
    public function needsRehash(string $hash): bool;
}
