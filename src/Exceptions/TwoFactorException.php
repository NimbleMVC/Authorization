<?php

namespace NimblePHP\Authorization\Exceptions;

use Exception;

/**
 * Exception thrown when two-factor authentication verification fails
 *
 * This exception is raised when a user provides an invalid or expired 2FA code.
 */
class TwoFactorException extends Exception
{
    /**
     * Create a new TwoFactorException
     *
     * @param string $message The exception message
     * @param int $code The exception code
     * @param Exception|null $previous The previous exception for exception chaining
     */
    public function __construct(string $message = "Two-factor authentication failed", int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
