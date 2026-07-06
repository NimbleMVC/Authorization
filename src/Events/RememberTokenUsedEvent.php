<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * RememberTokenUsedEvent - A remember-me token was successfully used to log in
 *
 * Dispatched before rotation; $selector identifies the consumed token
 * (the follow-up RememberTokenCreatedEvent carries the replacement).
 *
 * @package NimblePHP\Authorization\Events
 */
class RememberTokenUsedEvent extends AbstractEvent
{

    /**
     * @param int $accountId
     * @param string $selector Selector of the consumed token
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $selector
    ) {
    }

}
