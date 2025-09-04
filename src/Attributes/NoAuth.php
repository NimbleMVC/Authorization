<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;

/**
 * NoAuth attribute
 */
#[Attribute]
class NoAuth
{

    public function handle(object $controller): void
    {
    }

}