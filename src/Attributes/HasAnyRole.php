<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasAnyRole attribute - checks if user has any of the specified roles
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