<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAnyPermission attribute - checks if user has any of the specified permissions
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasAnyPermission
{
    /**
     * Array of permission names
     * @var array
     */
    private array $permissions;

    /**
     * Construct HasAnyPermission attribute
     * @param string ...$permissions
     */
    public function __construct(string ...$permissions)
    {
        $this->permissions = $permissions;
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

        if (!$authorization->hasAnyPermission($this->permissions)) {
            throw new UnauthorizedException("User does not have any of the required permissions: " . implode(', ', $this->permissions));
        }
    }

    /**
     * Get permissions array
     * @return array
     */
    public function getPermissions(): array
    {
        return $this->permissions;
    }
}