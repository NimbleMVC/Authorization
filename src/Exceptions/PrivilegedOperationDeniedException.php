<?php

namespace NimblePHP\Authorization\Exceptions;

use NimblePHP\Authorization\PrivilegedAction;
use NimblePHP\Framework\Exception\NimbleException;
use Throwable;

/**
 * A configured policy did not authorize a security-sensitive operation.
 */
final class PrivilegedOperationDeniedException extends NimbleException
{

    public function __construct(PrivilegedAction $action, ?Throwable $previous = null)
    {
        parent::__construct(
            sprintf('Privileged operation "%s" was denied', $action->value),
            403,
            $previous
        );
    }

}
