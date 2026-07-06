<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RoleRemovedEvent - Dispatched after a role is removed from an account
 *
 * Use for audit logging and permission cache invalidation.
 *
 * @package NimblePHP\Authorization\Events
 */
class RoleRemovedEvent extends AbstractEvent
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
