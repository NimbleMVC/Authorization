<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * LoginFailedEvent - Dispatched when a login attempt fails
 *
 * Use for activity logging, alerting and custom lockout logic.
 *
 * @package NimblePHP\Authorization\Events
 */
class LoginFailedEvent extends AbstractEvent
{

    public const REASON_USER_NOT_FOUND = 'user_not_found';
    public const REASON_INVALID_PASSWORD = 'invalid_password';
    public const REASON_NOT_ACTIVATED = 'not_activated';
    public const REASON_REJECTED = 'rejected';
    public const REASON_RATE_LIMITED = 'rate_limited';
    public const REASON_INVALID_TWO_FACTOR = 'invalid_two_factor';

    /**
     * @param string $login Login identifier used (username or email)
     * @param string $reason One of the REASON_* constants
     * @param array|null $account Account row if the account was found
     */
    public function __construct(
        public readonly string $login,
        public readonly string $reason,
        public readonly ?array $account = null
    ) {
    }

}
