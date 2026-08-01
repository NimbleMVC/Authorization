<?php

namespace NimblePHP\Authorization;

/**
 * Immutable input passed to the application's privileged-operation policy.
 */
final readonly class PrivilegedOperation
{

    /**
     * @param array<string, mixed> $context Non-secret metadata describing the operation.
     * @param object|null $evidence Application-owned proof, capability or verified result.
     */
    public function __construct(
        public PrivilegedAction $action,
        public ?int $actorAccountId = null,
        public ?int $targetAccountId = null,
        public array $context = [],
        public ?object $evidence = null
    ) {
    }

    /**
     * Nested model calls for the same action and target reuse an already approved
     * boundary without invoking the policy a second time.
     */
    public function boundaryKey(): string
    {
        return $this->action->value . ':' . ($this->targetAccountId ?? 'none');
    }

}
