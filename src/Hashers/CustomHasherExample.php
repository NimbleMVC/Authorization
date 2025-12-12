<?php

namespace NimblePHP\Authorization\Hashers;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

/**
 * CustomHasherExample - Example implementation of custom password hasher
 * 
 * Ten plik pokazuje jak zaimplementować własny hasher.
 * Możesz go skopiować i zmodyfikować dla swoich potrzeb.
 * 
 * Przykład użycia:
 * ```php
 * // W konfiguracji aplikacji
 * use App\Auth\MyCustomHasher;
 * use NimblePHP\Authorization\Config;
 * 
 * Config::setPasswordHasher(new MyCustomHasher());
 * ```
 * 
 * @package NimblePHP\Authorization\Hashers
 */
class CustomHasherExample implements PasswordHasher
{
    /**
     * Hash a password with custom algorithm
     * 
     * @param string $password Plain text password
     * @return string Hashed password
     */
    public function hash(string $password): string
    {
        // Przykład: SHA-256 z solą
        $salt = bin2hex(random_bytes(16));
        $hash = hash('sha256', $salt . $password);
        
        // Zapisz sól razem z hashem w formacie: $algorithm$salt$hash
        return '$custom$' . $salt . '$' . $hash;
    }

    /**
     * Verify password against hash
     * 
     * @param string $hash Stored hash
     * @param string $password Plain text password
     * @return bool True if password matches
     */
    public function verify(string $hash, string $password): bool
    {
        // Rozpakuj sól i hash
        $parts = explode('$', $hash);
        
        if (count($parts) < 4 || $parts[1] !== 'custom') {
            return false;
        }
        
        $salt = $parts[2];
        $storedHash = $parts[3];
        
        // Porównaj hash
        $computedHash = hash('sha256', $salt . $password);
        
        return hash_equals($storedHash, $computedHash);
    }

    /**
     * Check if hash needs rehashing
     * 
     * Przydatne gdy chcesz zmienić algorytm haszowania
     * 
     * @param string $hash Password hash to check
     * @return bool True if should be rehashed
     */
    public function needsRehash(string $hash): bool
    {
        // Jeśli hash nie używa naszego algorytmu, trzeba go wymienić
        return !str_starts_with($hash, '$custom$');
    }
}
