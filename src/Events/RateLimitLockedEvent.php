<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RateLimitLockedEvent - Dispatched when a lockout is created (not on every failed attempt)
 *
 * Use for alerting, audit, fail2ban-like reactions. For per-attempt logging
 * listen to LoginFailedEvent instead.
 *
 * @package NimblePHP\Authorization\Events
 */
class RateLimitLockedEvent extends AbstractEvent
{

    /**
     * @param string $identifier Locked identifier (login or "ip:<address>")
     * @param int $lockedUntil Unix timestamp when the lockout expires
     */
    public function __construct(
        public readonly string $identifier,
        public readonly int $lockedUntil
    ) {
    }

}
