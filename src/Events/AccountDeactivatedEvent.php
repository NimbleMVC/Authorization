<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * AccountDeactivatedEvent - Dispatched after an account is deactivated
 *
 * Use for session/token cleanup and audit.
 *
 * @package NimblePHP\Authorization\Events
 */
class AccountDeactivatedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     */
    public function __construct(
        public readonly int $accountId
    ) {
    }

}
