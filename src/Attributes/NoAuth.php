<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;

/**
 * NoAuth attribute - Disables default authorization for a method
 * 
 * Applied to controller methods to bypass authorization checks even if
 * AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT is enabled.
 * 
 * Usage:
 * ```php
 * #[NoAuth]
 * public function publicAction() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
 */
#[Attribute]
class NoAuth
{

    /**
     * Handle no-auth bypass
     * 
     * @param object $controller The controller instance
     * @return void
     */
    public function handle(object $controller): void
    {
    }

}