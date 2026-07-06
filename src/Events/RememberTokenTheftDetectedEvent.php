<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RememberTokenTheftDetectedEvent - Valid selector with a wrong validator
 *
 * The module has already invalidated all remember-me tokens of the account.
 * Use for security alerts, forced password change, audit logging.
 *
 * @package NimblePHP\Authorization\Events
 */
class RememberTokenTheftDetectedEvent extends AbstractEvent
{

    /**
     * @param int $accountId Account whose token was abused
     */
    public function __construct(
        public readonly int $accountId
    ) {
    }

}
