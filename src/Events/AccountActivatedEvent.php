<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * AccountActivatedEvent - Dispatched after an account is activated
 *
 * @package NimblePHP\Authorization\Events
 */
class AccountActivatedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     */
    public function __construct(
        public readonly int $accountId
    ) {
    }

}
