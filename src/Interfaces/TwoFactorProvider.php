<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * Interface for implementing two-factor authentication providers
 *
 * Implementations must provide methods for generating codes, verifying codes,
 * and managing 2FA secrets for users.
 */
interface TwoFactorProvider
{
    /**
     * Generate a new 2FA secret/key for the user
     *
     * @return string The generated secret key
     */
    public function generateSecret(): string;

    /**
     * Generate a verification code from a secret
     *
     * @param string $secret The 2FA secret key
     * @return string The generated verification code
     */
    public function generateCode(string $secret): string;

    /**
     * Verify if a code matches the secret
     *
     * @param string $secret The 2FA secret key
     * @param string $code The verification code to verify
     * @return bool True if code is valid, false otherwise
     */
    public function verify(string $secret, string $code): bool;

    /**
     * Check if the code is still valid (hasn't expired)
     *
     * Only applicable for time-based providers
     *
     * @param string $secret The 2FA secret key
     * @param string $code The verification code
     * @return bool True if code hasn't expired, false otherwise
     */
    public function isCodeValid(string $secret, string $code): bool;

    /**
     * Get the name of the 2FA provider
     *
     * Examples: 'totp', 'email', 'sms'
     *
     * @return string The provider name
     */
    public function getName(): string;

    /**
     * Get recovery codes (if supported by provider)
     *
     * Recovery codes are backup codes users can use if they lose access
     * to their 2FA device. If the provider doesn't support recovery codes,
     * return an empty array.
     *
     * @param string $secret The 2FA secret key
     * @return array<int, string> Array of recovery codes
     */
    public function getRecoveryCodes(string $secret): array;

    /**
     * Verify and consume a recovery code
     *
     * Recovery codes should be marked as used after verification.
     *
     * @param string $secret The 2FA secret key
     * @param string $code The recovery code to verify
     * @return bool True if recovery code is valid and unused
     */
    public function verifyRecoveryCode(string $secret, string $code): bool;
}
