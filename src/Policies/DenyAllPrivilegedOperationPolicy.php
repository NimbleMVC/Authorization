<?php

namespace NimblePHP\Authorization\Policies;

use NimblePHP\Authorization\Interfaces\PrivilegedOperationPolicy;
use NimblePHP\Authorization\PrivilegedOperation;

/**
 * Safe default: privileged operations are unavailable until explicitly enabled.
 */
final class DenyAllPrivilegedOperationPolicy implements PrivilegedOperationPolicy
{

    public function allows(PrivilegedOperation $operation): bool
    {
        return false;
    }

}
