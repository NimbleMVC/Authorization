<?php

namespace NimblePHP\Authorization\Hashers;

use Krzysztofzylka\Hash\VersionedHasher;
use NimblePHP\Authorization\Interfaces\PasswordHasher;

/**
 * DefaultPasswordHasher - Default implementation using VersionedHasher
 * 
 * Implementacja domyślna korzystająca z biblioteki `krzysztofzylka/hash`
 * która zapewnia bezpieczne haszowanie haseł z support'em dla różnych algorytmów.
 * 
 * @package NimblePHP\Authorization\Hashers
 */
class DefaultPasswordHasher implements PasswordHasher
{
    /**
     * Hash a password using VersionedHasher
     * 
     * @param string $password The plain text password to hash
     * @return string The hashed password
     */
    public function hash(string $password): string
    {
        return VersionedHasher::create($password);
    }

    /**
     * Verify a password against a hash
     * 
     * @param string $hash The stored password hash
     * @param string $password The plain text password to verify
     * @return bool True if password matches hash, false otherwise
     */
    public function verify(string $hash, string $password): bool
    {
        return VersionedHasher::verify($hash, $password);
    }

    /**
     * Check if a hash needs to be rehashed
     * 
     * @param string $hash The password hash to check
     * @return bool True if hash should be rehashed with newer algorithm
     */
    public function needsRehash(string $hash): bool
    {
        return VersionedHasher::needsRehash($hash);
    }
}
