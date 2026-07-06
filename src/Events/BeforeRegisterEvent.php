<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * BeforeRegisterEvent - Dispatched after validation, before the account is inserted
 *
 * Listeners can veto the registration (password policy, invitations, captcha)
 * or enrich the inserted row via $extraData (merged into the insert).
 *
 * @package NimblePHP\Authorization\Events
 */
class BeforeRegisterEvent extends AbstractEvent
{

    /**
     * Additional columns merged into the account insert
     * @var array
     */
    public array $extraData = [];

    /**
     * Rejection reason set by a listener
     * @var string|null
     */
    private ?string $rejectReason = null;

    /**
     * @param string $username
     * @param string|null $email
     * @param string $password Plaintext password (for strength/HIBP checks)
     */
    public function __construct(
        public readonly string $username,
        public readonly ?string $email,
        public readonly string $password
    ) {
    }

    /**
     * Veto the registration
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

}
