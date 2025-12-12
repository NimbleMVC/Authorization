<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * Interface for implementing token-based authentication providers
 *
 * Supports JWT, API Keys, and similar token-based authentication methods
 */
interface TokenProvider
{
    /**
     * Generate a new token
     *
     * @param int $userId User ID
     * @param array $claims Additional claims/metadata
     * @param int|null $expiresIn Token expiration time in seconds (null = no expiration)
     * @return string The generated token
     * @throws \Exception If token generation fails
     */
    public function generateToken(int $userId, array $claims = [], ?int $expiresIn = null): string;

    /**
     * Validate a token
     *
     * @param string $token Token to validate
     * @return array Token data (must include 'user_id' at minimum)
     * @throws \Exception If token is invalid or expired
     */
    public function validateToken(string $token): array;

    /**
     * Get token type
     *
     * @return string Token type name (e.g., 'jwt', 'api_key')
     */
    public function getTokenType(): string;

    /**
     * Revoke a token
     *
     * @param string $token Token to revoke
     * @return bool True if revocation was successful
     */
    public function revokeToken(string $token): bool;

    /**
     * Check if token is revoked
     *
     * @param string $token Token to check
     * @return bool True if token is revoked
     */
    public function isTokenRevoked(string $token): bool;
}
