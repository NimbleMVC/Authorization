<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAllRoles attribute - Checks if user has all of the specified roles
 * 
 * Applied to controller methods to verify the authenticated user has all of
 * the specified roles. If user doesn't have all roles, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[HasAllRoles('admin', 'superuser')]
 * public function restrictedAction() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasAllRoles
{
    /**
     * Array of role names
     * @var array
     */
    private array $roles;

    /**
     * Construct HasAllRoles attribute
     * @param string ...$roles Variable number of role names to check
     */
    public function __construct(string ...$roles)
    {
        $this->roles = $roles;
    }

    /**
     * Handle the role check
     * @param object $controller The controller instance
     * @return void
     * @throws UnauthorizedException If user doesn't have all of the roles
     */
    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->hasAllRoles($this->roles)) {
            throw new UnauthorizedException("User does not have all of the required roles: " . implode(', ', $this->roles));
        }
    }

    /**
     * Get roles array
     * @return array
     */
    public function getRoles(): array
    {
        return $this->roles;
    }
}