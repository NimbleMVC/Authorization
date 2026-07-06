<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * BeforeLoginEvent - Dispatched after credentials are verified, before the session is created
 *
 * Listeners can veto the login (e.g. banned account, custom business rules)
 * by calling reject() with a user-facing reason. The login pipeline then
 * throws a ValidationException with that reason.
 *
 * @package NimblePHP\Authorization\Events
 */
class BeforeLoginEvent extends AbstractEvent
{

    /**
     * Rejection reason set by a listener
     * @var string|null
     */
    private ?string $rejectReason = null;

    /**
     * Challenge required by a listener (e.g. a 2FA module)
     * @var string|null
     */
    private ?string $requiredChallenge = null;

    /**
     * @param string $login Login identifier used (username or email)
     * @param array $account Account row fetched from database
     */
    public function __construct(
        public readonly string $login,
        public readonly array $account
    ) {
    }

    /**
     * Veto the login attempt
     * @param string $reason User-facing reason
     * @return void
     */
    public function reject(string $reason): void
    {
        $this->rejectReason = $reason;
        $this->stopPropagation();
    }

    /**
     * @return bool
     */
    public function isRejected(): bool
    {
        return $this->rejectReason !== null;
    }

    /**
     * @return string|null
     */
    public function getRejectReason(): ?string
    {
        return $this->rejectReason;
    }

    /**
     * Require an additional challenge before the session is created
     *
     * Credentials stay verified; login() stores a pending state and throws
     * PendingChallengeException. Complete with Authorization::completeChallenge().
     * @param string $name Challenge name (e.g. 'totp')
     * @return void
     */
    public function requireChallenge(string $name): void
    {
        $this->requiredChallenge = $name;
    }

    /**
     * @return string|null
     */
    public function getRequiredChallenge(): ?string
    {
        return $this->requiredChallenge;
    }

}
