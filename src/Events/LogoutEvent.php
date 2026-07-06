<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * LogoutEvent - Dispatched after the user session is cleared
 *
 * @package NimblePHP\Authorization\Events
 */
class LogoutEvent extends AbstractEvent
{

    /**
     * @param int|null $accountId Account id that was logged out (null if no session existed)
     */
    public function __construct(
        public readonly ?int $accountId
    ) {
    }

}
