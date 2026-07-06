<?php

namespace NimblePHP\Authorization\Events;

use NimblePHP\Framework\Event\AbstractEvent;

/**
 * BeforePasswordChangeEvent - Dispatched before a user-initiated password change
 *
 * Listeners can veto (password policy, HIBP). Not dispatched for internal
 * rehash during login.
 *
 * @package NimblePHP\Authorization\Events
 */
class BeforePasswordChangeEvent extends AbstractEvent
{

    /**
     * Rejection reason set by a listener
     * @var string|null
     */
    private ?string $rejectReason = null;

    /**
     * @param int $accountId
     * @param string $password Plaintext password (for strength/HIBP checks)
     */
    public function __construct(
        public readonly int $accountId,
        public readonly string $password
    ) {
    }

    /**
     * Veto the password change
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
