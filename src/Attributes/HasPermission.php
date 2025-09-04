<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasPermission attribute - checks if user has specific permission
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
     * @param string $permission
     */
    public function __construct(string $permission)
    {
        $this->permission = $permission;
    }

    /**
     * Handle the permission check
     * @param object $controller
     * @return void
     * @throws UnauthorizedException
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