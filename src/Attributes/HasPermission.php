<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasPermission attribute - Checks if user has specific permission
 * 
 * Applied to controller methods to verify the authenticated user has the specified permission.
 * If user doesn't have the permission, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[HasPermission('delete.users')]
 * public function deleteUser() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class HasPermission
{
    /**
     * Permission name
     * @var string
     */
    private string $permission;

    /**
     * Construct HasPermission attribute
     * @param string $permission The permission name to check
     */
    public function __construct(string $permission)
    {
        $this->permission = $permission;
    }

    /**
     * Handle the permission check
     * @param object $controller The controller instance
     * @return void
     * @throws UnauthorizedException If user doesn't have the permission
     */
    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->hasPermission($this->permission)) {
            throw new UnauthorizedException("User does not have required permission: {$this->permission}");
        }
    }

    /**
     * Get permission name
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }
}