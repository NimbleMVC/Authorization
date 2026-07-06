<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * AuthorizationConfiguredEvent - Module registered and Config initialized
 *
 * Dispatched at the end of Module::register(). Extension modules (2fa,
 * social-login, api-tokens) should hook here to register their providers
 * and listeners without depending on module load order.
 *
 * @package NimblePHP\Authorization\Events
 */
class AuthorizationConfiguredEvent extends AbstractEvent
{

}
