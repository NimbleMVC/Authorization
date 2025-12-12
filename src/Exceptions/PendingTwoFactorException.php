<?php

namespace NimblePHP\Authorization\Exceptions;

use Exception;

/**
 * Exception thrown when user has not yet completed two-factor authentication
 *
 * This exception is raised during login when a user has provided valid credentials
 * but still needs to complete the 2FA verification step. This allows the application
 * to identify that 2FA is pending and redirect to the 2FA verification page.
 *
 * The exception contains session data that should be preserved until 2FA is completed.
 */
class PendingTwoFactorException extends Exception
{
    /**
     * The user ID pending 2FA verification
     *
     * @var int
     */
    private int $userId;

    /**
     * The 2FA provider being used
     *
     * @var string
     */
    private string $provider;

    /**
     * Create a new PendingTwoFactorException
     *
     * @param int $userId The user ID
     * @param string $provider The 2FA provider name (e.g., 'totp', 'email')
     * @param string $message Optional message
     */
    public function __construct(int $userId, string $provider, string $message = "Two-factor authentication is required")
    {
        parent::__construct($message);
        $this->userId = $userId;
        $this->provider = $provider;
    }

    /**
     * Get the user ID
     *
     * @return int The user ID
     */
    public function getUserId(): int
    {
        return $this->userId;
    }

    /**
     * Get the 2FA provider
     *
     * @return string The provider name
     */
    public function getProvider(): string
    {
        return $this->provider;
    }
}
