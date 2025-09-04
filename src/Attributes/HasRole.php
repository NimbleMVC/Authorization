<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;

/**
 * HasRole attribute - checks if user has specific role
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class HasRole
{
    /**
     * Role name
     * @var string
     */
    private string $role;

    /**
     * Construct HasRole attribute
     * @param string $role
     */
    public function __construct(string $role)
    {
        $this->role = $role;
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

        if (!$authorization->hasRole($this->role)) {
            throw new UnauthorizedException("User does not have required role: {$this->role}");
        }
    }

    /**
     * Get role name
     * @return string
     */
    public function getRole(): string
    {
        return $this->role;
    }
}