<?php

namespace NimblePHP\Authorization\Interfaces;

use NimblePHP\Authorization\PrivilegedOperation;

/**
 * Application-owned authorization boundary for high-trust library operations.
 */
interface PrivilegedOperationPolicy
{

    public function allows(PrivilegedOperation $operation): bool;

}
