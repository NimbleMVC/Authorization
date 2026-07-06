<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * LoginSuccessEvent - Dispatched after the user session is created
 *
 * Use for activity logging, last-login timestamps, remember-me issuing etc.
 *
 * @package NimblePHP\Authorization\Events
 */
class LoginSuccessEvent extends AbstractEvent
{

    public const METHOD_PASSWORD = 'password';
    public const METHOD_TWO_FACTOR = 'two_factor';
    public const METHOD_OAUTH = 'oauth';
    public const METHOD_TOKEN = 'token';
    public const METHOD_REMEMBER_ME = 'remember_me';

    /**
     * @param int $accountId Authenticated account id
     * @param array $account Account row (may be empty for token-based auth)
     * @param string $method One of the METHOD_* constants
     */
    public function __construct(
        public readonly int $accountId,
        public readonly array $account,
        public readonly string $method
    ) {
    }

}
