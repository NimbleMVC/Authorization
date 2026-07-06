<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * AfterRegisterEvent - Dispatched after the account row is inserted
 *
 * Use for activation e-mails, marking invitations as used, default roles etc.
 *
 * @package NimblePHP\Authorization\Events
 */
class AfterRegisterEvent extends AbstractEvent
{

    /**
     * @param int $accountId New account id
     * @param array $data Inserted row data (password already hashed)
     */
    public function __construct(
        public readonly int $accountId,
        public readonly array $data
    ) {
    }

}
