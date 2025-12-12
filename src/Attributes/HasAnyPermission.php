<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAnyPermission attribute - Checks if user has any of the specified permissions
 * 
 * Applied to controller methods to verify the authenticated user has at least one of
 * the specified permissions. If user doesn't have any permission, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[HasAnyPermission('create.posts', 'edit.posts')]
 * public function managePost() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
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
     * @param string ...$permissions Variable number of permission names to check
     */
    public function __construct(string ...$permissions)
    {
        $this->permissions = $permissions;
    }

    /**
     * Handle the permission check
     * @param object $controller The controller instance
     * @return void
     * @throws UnauthorizedException If user doesn't have any of the permissions
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