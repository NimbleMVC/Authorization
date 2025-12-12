<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\TwoFactorProvider;

/**
 * Email-based two-factor authentication provider
 *
 * Sends verification codes to user's email address.
 * Codes are numeric and time-limited (default 10 minutes).
 */
class EmailProvider implements TwoFactorProvider
{
    /**
     * Length of the OTP code
     *
     * @var int
     */
    private int $codeLength = 6;

    /**
     * Code validity duration in seconds (default: 600 = 10 minutes)
     *
     * @var int
     */
    private int $codeDuration = 600;

    /**
     * Callback function to send emails
     *
     * @var callable|null
     */
    private $emailCallback = null;

    /**
     * Store for active codes (in production, use Redis or database)
     *
     * @var array<string, array{code: string, expires: int, attempts: int}>
     */
    private array $activeCodes = [];

    /**
     * Create a new EmailProvider
     *
     * @param int $codeLength Length of the verification code (default: 6)
     * @param int $codeDuration Duration in seconds for code validity (default: 600)
     */
    public function __construct(int $codeLength = 6, int $codeDuration = 600)
    {
        $this->codeLength = $codeLength;
        $this->codeDuration = $codeDuration;
    }

    /**
     * Set the email callback function
     *
     * The callback receives (email, code) parameters:
     * $provider->setEmailCallback(function($email, $code) {
     *     // Send email with code
     * });
     *
     * @param callable $callback Function to send emails
     * @return void
     */
    public function setEmailCallback(callable $callback): void
    {
        $this->emailCallback = $callback;
    }

    /**
     * Generate a new secret (not used for email provider, returns empty string)
     *
     * @return string Empty string
     */
    public function generateSecret(): string
    {
        return '';
    }

    /**
     * Generate a verification code and send it via email
     *
     * @param string $secret The email address (passed as secret parameter)
     * @return string The generated code
     */
    public function generateCode(string $secret): string
    {
        $code = $this->generateRandomCode();
        $email = $secret;

        $this->activeCodes[$email] = [
            'code' => $code,
            'expires' => time() + $this->codeDuration,
            'attempts' => 0,
        ];

        if ($this->emailCallback !== null) {
            call_user_func($this->emailCallback, $email, $code);
        }

        return $code;
    }

    /**
     * Verify an email verification code
     *
     * @param string $secret The email address
     * @param string $code The code to verify
     * @return bool True if code is valid
     */
    public function verify(string $secret, string $code): bool
    {
        return $this->isCodeValid($secret, $code);
    }

    /**
     * Check if a code is valid and not expired
     *
     * @param string $secret The email address
     * @param string $code The code to verify
     * @return bool True if code is valid, false if expired or wrong
     */
    public function isCodeValid(string $secret, string $code): bool
    {
        $email = $secret;

        if (!isset($this->activeCodes[$email])) {
            return false;
        }

        $stored = $this->activeCodes[$email];

        if (time() > $stored['expires']) {
            unset($this->activeCodes[$email]);
            return false;
        }

        if (!hash_equals($stored['code'], $code)) {
            $stored['attempts']++;

            if ($stored['attempts'] >= 5) {
                unset($this->activeCodes[$email]);
                return false;
            }

            $this->activeCodes[$email] = $stored;
            return false;
        }

        unset($this->activeCodes[$email]);
        return true;
    }

    /**
     * Get the provider name
     *
     * @return string Always returns 'email'
     */
    public function getName(): string
    {
        return 'email';
    }

    /**
     * Recovery codes are not used for email provider
     *
     * @param string $secret Not used
     * @return array Empty array
     */
    public function getRecoveryCodes(string $secret): array
    {
        return [];
    }

    /**
     * Verify recovery code (not supported for email provider)
     *
     * @param string $secret Not used
     * @param string $code Not used
     * @return bool Always returns false
     */
    public function verifyRecoveryCode(string $secret, string $code): bool
    {
        return false;
    }

    /**
     * Get the remaining time for code validity
     *
     * @param string $email Email address
     * @return int Remaining seconds, or -1 if code not found
     */
    public function getRemainingTime(string $email): int
    {
        if (!isset($this->activeCodes[$email])) {
            return -1;
        }

        $remaining = $this->activeCodes[$email]['expires'] - time();
        return max(0, $remaining);
    }

    /**
     * Clear a code (user resends code request)
     *
     * @param string $email Email address
     * @return void
     */
    public function clearCode(string $email): void
    {
        unset($this->activeCodes[$email]);
    }

    /**
     * Generate a random numeric code
     *
     * @return string The generated code
     */
    private function generateRandomCode(): string
    {
        $code = random_int(0, pow(10, $this->codeLength) - 1);
        return str_pad((string)$code, $this->codeLength, '0', STR_PAD_LEFT);
    }
}
