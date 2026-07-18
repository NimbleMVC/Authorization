<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\OAuth;

use InvalidArgumentException;

/**
 * Immutable identity established by a completed OAuth callback.
 *
 * Applications should obtain this value from Authorization::handleOAuthCallback()
 * and pass it unchanged to loginWithOAuth() or linkOAuthIdentity().
 */
final readonly class OAuthIdentity
{
    public string $provider;
    public string $subject;
    public string $username;
    public string $email;
    public bool $emailVerified;

    public function __construct(
        string $provider,
        string $subject,
        string $username,
        string $email,
        bool $emailVerified,
    ) {
        $provider = trim($provider);
        $subject = trim($subject);
        $username = trim($username);
        $email = trim($email);

        if ($provider === '' || strlen($provider) > 50) {
            throw new InvalidArgumentException('OAuth provider must be a non-empty string up to 50 characters');
        }

        if ($subject === '' || strlen($subject) > 255) {
            throw new InvalidArgumentException('OAuth subject must be a non-empty string up to 255 characters');
        }

        if ($username === '') {
            throw new InvalidArgumentException('OAuth username cannot be empty');
        }

        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new InvalidArgumentException('OAuth e-mail address is invalid');
        }

        $this->provider = $provider;
        $this->subject = $subject;
        $this->username = $username;
        $this->email = $email;
        $this->emailVerified = $emailVerified;
    }

    /**
     * Normalize provider output after state validation and token exchange.
     *
     * @param array<string, mixed> $providerData
     */
    public static function fromProviderCallback(string $provider, array $providerData): self
    {
        if (
            isset($providerData['oauth_provider'])
            && (!is_string($providerData['oauth_provider']) || !hash_equals($provider, $providerData['oauth_provider']))
        ) {
            throw new InvalidArgumentException('OAuth provider identity does not match the callback provider');
        }

        return new self(
            provider: $provider,
            subject: is_scalar($providerData['oauth_id'] ?? null) ? (string)$providerData['oauth_id'] : '',
            username: is_string($providerData['username'] ?? null) ? $providerData['username'] : '',
            email: is_string($providerData['email'] ?? null) ? $providerData['email'] : '',
            emailVerified: ($providerData['email_verified'] ?? false) === true,
        );
    }
}
