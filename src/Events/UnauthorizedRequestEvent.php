<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * UnauthorizedRequestEvent - Unauthenticated request hit a protected action
 *
 * Dispatched just before the configured UnauthorizedHandler runs.
 * Use for audit logging, monitoring and diagnostics of unauthorized hits.
 *
 * @package NimblePHP\Authorization\Events
 */
class UnauthorizedRequestEvent extends AbstractEvent
{

    /**
     * @param string $uri Requested URI
     * @param bool $isApiRequest Result of the API request detection cascade
     */
    public function __construct(
        public readonly string $uri,
        public readonly bool $isApiRequest
    ) {
    }

}
