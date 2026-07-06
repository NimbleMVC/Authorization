<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RoleAssignedEvent - Dispatched after a role is assigned to an account
 *
 * Use for audit logging, permission cache invalidation, notifications.
 *
 * @package NimblePHP\Authorization\Events
 */
class RoleAssignedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     * @param string $roleName
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $roleName
    ) {
    }

}
