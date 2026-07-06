<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * UnauthorizedHandler Interface - Reaction to an unauthenticated request
 *
 * Implementations decide what happens when a protected controller action
 * is reached without authentication: throw an exception, redirect to the
 * login page, send a JSON 401 response etc.
 *
 * Register a custom handler via:
 * ```php
 * Config::setUnauthorizedHandler(new MyHandler());
 * ```
 *
 * @package NimblePHP\Authorization\Interfaces
 */
interface UnauthorizedHandler
{

    /**
     * Handle an unauthenticated request
     *
     * Implementations are expected to interrupt request processing
     * (throw, redirect or send a response and exit).
     *
     * @return void
     */
    public function handle(): void;

}
