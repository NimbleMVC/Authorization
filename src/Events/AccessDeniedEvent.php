<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * AccessDeniedEvent - Authenticated user failed a role/permission attribute check
 *
 * Dispatched right before the UnauthorizedException is thrown.
 * Use for audit logging ("user #5 tried to access the admin page") and alerting.
 *
 * @package NimblePHP\Authorization\Events
 */
class AccessDeniedEvent extends AbstractEvent
{

    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';
    public const TYPE_ANY_ROLE = 'any_role';
    public const TYPE_ALL_ROLES = 'all_roles';
    public const TYPE_ANY_PERMISSION = 'any_permission';

    /**
     * @param int $accountId Authenticated account that was denied
     * @param string $requirement Required role/permission name(s), comma separated for lists
     * @param string $type One of the TYPE_* constants
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $requirement,
        public readonly string $type
    ) {
    }

}
