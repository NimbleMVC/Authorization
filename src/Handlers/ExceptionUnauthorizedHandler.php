<?php

namespace NimblePHP\Authorization\Handlers;

use NimblePHP\Authorization\Exceptions\UnauthorizedException;
use NimblePHP\Authorization\Interfaces\UnauthorizedHandler;

/**
 * ExceptionUnauthorizedHandler - Default handler, throws UnauthorizedException
 *
 * Preserves the historical behaviour of the module: an unauthenticated
 * request to a protected action results in a 401 UnauthorizedException.
 *
 * @package NimblePHP\Authorization\Handlers
 */
class ExceptionUnauthorizedHandler implements UnauthorizedHandler
{

    /**
     * @return void
     * @throws UnauthorizedException
     */
    public function handle(): void
    {
        throw new UnauthorizedException();
    }

}
