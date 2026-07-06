<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RolePermissionChangedEvent - Permissions of a role changed (add/remove/replace)
 *
 * Affects every account holding the role - invalidate permission caches broadly.
 *
 * @package NimblePHP\Authorization\Events
 */
class RolePermissionChangedEvent extends AbstractEvent
{

    /**
     * @param int $roleId
     * @param string|null $roleName Null when the name could not be resolved
     */
    public function __construct(
        public readonly int $roleId,
        public readonly ?string $roleName
    ) {
    }

}
