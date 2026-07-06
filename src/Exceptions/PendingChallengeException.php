<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Framework\Exception\NimbleException;

/**
 * PendingChallengeException - Credentials verified, but a listener requires a challenge
 *
 * Thrown by Authorization::login() when a BeforeLoginEvent listener called
 * requireChallenge() (e.g. a 2FA module). The pending state is stored in the
 * session; after verifying the challenge call Authorization::completeChallenge().
 *
 * @package NimblePHP\Authorization\Exceptions
 */
class PendingChallengeException extends NimbleException
{

    /**
     * @param int $accountId Account waiting for the challenge
     * @param string $challenge Challenge name (e.g. 'totp')
     * @param string $message
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $challenge,
        string $message = 'Additional authentication challenge required'
    ) {
        parent::__construct($message, 401);
    }

}
