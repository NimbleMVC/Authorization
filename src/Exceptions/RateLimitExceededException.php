<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Framework\Exception\NimbleException;

/**
 * RateLimitExceededException - Thrown when login rate limit is exceeded
 * 
 * This exception is raised when:
 * - User exceeds maximum login attempts
 * - Account is locked due to brute force protection
 * - Too many failed login attempts from same identifier
 * 
 * HTTP Status Code: 429 Too Many Requests
 * 
 * @package NimblePHP\Authorization\Exceptions
 */
class RateLimitExceededException extends NimbleException
{

    /**
     * Construct the RateLimitExceededException instance
     * 
     * @param string $message The error message
     * @param int $retryAfter Seconds until user can retry (optional)
     */
    public function __construct(string $message = 'Too many login attempts', int $retryAfter = 0)
    {
        parent::__construct($message, 429);
    }

}
