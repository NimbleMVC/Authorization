<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * RequireAuth attribute - Requires user to be authenticated
 * 
 * Applied to controller methods to enforce that the user must be logged in.
 * If user is not authenticated, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[RequireAuth]
 * public function protectedAction() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
 */
#[Attribute]
class RequireAuth
{

    /**
     * Handle authentication check
     * 
     * @param object $controller The controller instance
     * @return void
     * @throws UnauthorizedException If user is not authorized
     */
    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->isAuthorized()) {
            throw new UnauthorizedException();
        }
    }

}