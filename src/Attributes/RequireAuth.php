<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * RequireAuth attribute
 */
#[Attribute]
class RequireAuth
{

    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->isAuthorized()) {
            throw new UnauthorizedException();
        }
    }

}