<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAnyRole attribute - Checks if user has any of the specified roles
 * 
 * Applied to controller methods to verify the authenticated user has at least one of
 * the specified roles. If user doesn't have any of the roles, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[HasAnyRole('admin', 'moderator')]
 * public function moderateContent() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasAnyRole
{
    /**
     * Array of role names
     * @var array
     */
    private array $roles;

    /**
     * Construct HasAnyRole attribute
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
     * @throws UnauthorizedException If user doesn't have any of the roles
     */
    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->hasAnyRole($this->roles)) {
            throw new UnauthorizedException("User does not have any of the required roles: " . implode(', ', $this->roles));
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