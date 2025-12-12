<?php

namespace NimblePHP\Authorization\Hashers;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

/**
 * ArgonPasswordHasher - Implementation using PHP's password_hash with Argon2
 * 
 * Najnowsza i najbardziej bezpieczna implementacja wykorzystująca Argon2,
 * winner Password Hashing Competition (2015). Najlepszy wybór dla aplikacji
 * wymagających najwyższego poziomu bezpieczeństwa.
 * 
 * Uwaga: Wymaga PHP >= 7.2
 * 
 * Konfiguracja:
 * ```php
 * Config::setPasswordHasher(new ArgonPasswordHasher(
 *     algorithm: PASSWORD_ARGON2ID,  // lub PASSWORD_ARGON2I
 *     memoryLimit: 65536,
 *     timeCost: 4,
 *     parallelism: 1
 * ));
 * ```
 * 
 * @package NimblePHP\Authorization\Hashers
 */
class ArgonPasswordHasher implements PasswordHasher
{
    /**
     * Argon algorithm (PASSWORD_ARGON2I or PASSWORD_ARGON2ID)
     * @var int
     */
    private int $algorithm;

    /**
     * Memory limit in KiB
     * @var int
     */
    private int $memoryLimit;

    /**
     * Time cost (iterations)
     * @var int
     */
    private int $timeCost;

    /**
     * Parallelism (threads/processes)
     * @var int
     */
    private int $parallelism;

    /**
     * Construct ArgonPasswordHasher
     * 
     * @param int $algorithm PASSWORD_ARGON2I or PASSWORD_ARGON2ID (default: PASSWORD_ARGON2ID)
     * @param int $memoryLimit Memory limit in KiB (default: 65536)
     * @param int $timeCost Time cost in iterations (default: 4)
     * @param int $parallelism Parallelism factor (default: 1)
     */
    public function __construct(
        int $algorithm = PASSWORD_ARGON2ID,
        int $memoryLimit = 65536,
        int $timeCost = 4,
        int $parallelism = 1
    ) {
        $this->algorithm = $algorithm;
        $this->memoryLimit = $memoryLimit;
        $this->timeCost = $timeCost;
        $this->parallelism = $parallelism;
    }

    /**
     * Hash a password using Argon2
     * 
     * @param string $password The plain text password to hash
     * @return string The hashed password
     */
    public function hash(string $password): string
    {
        return password_hash($password, $this->algorithm, [
            'memory_cost' => $this->memoryLimit,
            'time_cost' => $this->timeCost,
            'threads' => $this->parallelism,
        ]);
    }

    /**
     * Verify a password against an Argon2 hash
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
     * @param string $hash The password hash to check
     * @return bool True if hash should be rehashed
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, [
            'memory_cost' => $this->memoryLimit,
            'time_cost' => $this->timeCost,
            'threads' => $this->parallelism,
        ]);
    }

    /**
     * Set memory limit
     * 
     * @param int $memoryLimit Memory limit in KiB
     * @return void
     */
    public function setMemoryLimit(int $memoryLimit): void
    {
        $this->memoryLimit = $memoryLimit;
    }

    /**
     * Set time cost
     * 
     * @param int $timeCost Time cost iterations
     * @return void
     */
    public function setTimeCost(int $timeCost): void
    {
        $this->timeCost = $timeCost;
    }

    /**
     * Set parallelism
     * 
     * @param int $parallelism Parallelism factor
     * @return void
     */
    public function setParallelism(int $parallelism): void
    {
        $this->parallelism = $parallelism;
    }
}
