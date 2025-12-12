<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * Interface for implementing OAuth2 providers
 *
 * Implementations provide OAuth2 authentication flow for social login.
 */
interface OAuthProvider
{
    /**
     * Get the authorization URL where user should be redirected
     *
     * @param string $redirectUri The callback URL after user authorizes
     * @param array $scopes Optional scopes to request
     * @return string The authorization URL
     */
    public function getAuthorizationUrl(string $redirectUri, array $scopes = []): string;

    /**
     * Exchange authorization code for access token
     *
     * @param string $code The authorization code from callback
     * @param string $redirectUri The same redirect URI used in getAuthorizationUrl
     * @return string The access token
     * @throws \Exception If code exchange fails
     */
    public function exchangeCodeForToken(string $code, string $redirectUri): string;

    /**
     * Get user info from OAuth provider
     *
     * @param string $accessToken The access token
     * @return array User data (at minimum: id, email, name)
     * @throws \Exception If user data retrieval fails
     */
    public function getUserData(string $accessToken): array;

    /**
     * Get the provider name
     *
     * @return string The provider name (e.g., 'github', 'google')
     */
    public function getName(): string;

    /**
     * Get client ID
     *
     * @return string
     */
    public function getClientId(): string;

    /**
     * Get client secret
     *
     * @return string
     */
    public function getClientSecret(): string;
}
