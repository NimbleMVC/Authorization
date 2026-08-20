<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Framework\Exception\NimbleException;

/**
 * InsufficientScopeException - Thrown when a token/API key does not carry a scope
 * required by the caller (see APIKeyProvider::requireScope())
 *
 * HTTP Status Code: 403 Forbidden
 *
 * @package NimblePHP\Authorization\Exceptions
 */
class InsufficientScopeException extends NimbleException
{

    /**
     * Construct the InsufficientScopeException instance
     *
     * @param string $message The error message
     */
    public function __construct(string $message = 'Missing required scope')
    {
        parent::__construct($message, 403);
    }

}
