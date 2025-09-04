<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Framework\Exception\NimbleException;

class UnauthorizedException extends NimbleException
{

    /**
     * Construct the UnauthorizedException instance
     */

    public function __construct(string $message = 'Unauthorized')
    {
        parent::__construct($message, 401);
    }

}