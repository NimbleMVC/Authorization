<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAllRoles attribute - checks if user has all of the specified roles
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
     * @param string ...$roles
     */
    public function __construct(string ...$roles)
    {
        $this->roles = $roles;
    }

    /**
     * Handle the role check
     * @param object $controller
     * @return void
     * @throws UnauthorizedException
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