<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Framework\Exception\NimbleException;

/**
 * UnauthorizedException - Thrown when user is not authorized to perform an action
 * 
 * This exception is raised when:
 * - User is not authenticated (not logged in)
 * - User lacks required permissions or roles
 * - Protected resource is accessed without proper authorization
 * 
 * HTTP Status Code: 401 Unauthorized
 * 
 * @package NimblePHP\Authorization\Exceptions
 */
class UnauthorizedException extends NimbleException
{

    /**
     * Construct the UnauthorizedException instance
     * 
     * @param string $message The error message (default: 'Unauthorized')
     */

    public function __construct(string $message = 'Unauthorized')
    {
        parent::__construct($message, 401);
    }

}