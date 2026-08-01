<?php

namespace NimblePHP\Authorization\Policies;

use Closure;
use NimblePHP\Authorization\Interfaces\PrivilegedOperationPolicy;
use NimblePHP\Authorization\PrivilegedOperation;

/**
 * Convenience adapter for an application policy implemented as a callback.
 */
final class CallbackPrivilegedOperationPolicy implements PrivilegedOperationPolicy
{

    /** @var Closure(PrivilegedOperation): bool */
    private Closure $callback;

    /**
     * @param callable(PrivilegedOperation): bool $callback
     */
    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function allows(PrivilegedOperation $operation): bool
    {
        return ($this->callback)($operation) === true;
    }

}
