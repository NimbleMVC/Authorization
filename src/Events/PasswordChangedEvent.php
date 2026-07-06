<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * PasswordChangedEvent - Dispatched after a user-initiated password change
 *
 * Use for "logout everywhere", security notifications, audit.
 * Not dispatched for internal rehash during login.
 *
 * @package NimblePHP\Authorization\Events
 */
class PasswordChangedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     */
    public function __construct(
        public readonly int $accountId
    ) {
    }

}
