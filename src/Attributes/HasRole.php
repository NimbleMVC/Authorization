<?php

namespace NimblePHP\Authorization\Attributes;

use Attribute;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Events\AccessDeniedEvent;
use NimblePHP\Framework\Kernel;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;
use NimblePHP\Framework\Translation\Translation;

/**
 * HasRole attribute - Checks if user has specific role
 * 
 * Applied to controller methods to verify the authenticated user has the specified role.
 * If user doesn't have the role, UnauthorizedException is thrown.
 * 
 * Usage:
 * ```php
 * #[HasRole('admin')]
 * public function adminPanel() { ... }
 * ```
 * 
 * @package NimblePHP\Authorization\Attributes
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
     * @param string $role The role name to check
     */
    public function __construct(string $role)
    {
        $this->role = $role;
    }

    /**
     * Handle the role check
     * @param object $controller The controller instance
     * @return void
     * @throws UnauthorizedException If user doesn't have the role
     */
    public function handle(object $controller): void
    {
        $authorization = new Authorization();

        if (!$authorization->hasRole($this->role)) {
            Kernel::dispatchEvent(new AccessDeniedEvent($authorization->getAuthorizedId(), $this->role, AccessDeniedEvent::TYPE_ROLE));
            throw new UnauthorizedException(Translation::getInstance()->translate('module.authorization.errors.user_missing_role', ['role' => $this->role]));
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