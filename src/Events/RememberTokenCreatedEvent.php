<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RememberTokenCreatedEvent - A remember-me token was issued (also on rotation)
 *
 * Use by device-session modules to bind tokens to devices (user agent, IP).
 *
 * @package NimblePHP\Authorization\Events
 */
class RememberTokenCreatedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     * @param string $selector Public token selector (safe to store/reference)
     * @param string $expiresAt Expiry datetime (Y-m-d H:i:s)
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $selector,
        public readonly string $expiresAt
    ) {
    }

}
