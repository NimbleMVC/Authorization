<?php

namespace NimblePHP\Authorization\Services;

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\PrivilegedOperationDeniedException;
use NimblePHP\Authorization\PrivilegedOperation;
use Throwable;

/**
 * Executes privileged callbacks only after an explicit policy decision.
 */
final class PrivilegedOperationGate
{

    /** @var array<string, int> */
    private static array $activeBoundaries = [];

    /**
     * @template T
     * @param callable(): T $callback
     * @return T
     * @throws PrivilegedOperationDeniedException
     */
    public static function execute(PrivilegedOperation $operation, callable $callback): mixed
    {
        $boundaryKey = $operation->boundaryKey();

        if (!isset(self::$activeBoundaries[$boundaryKey])) {
            try {
                $allowed = Config::getPrivilegedOperationPolicy()->allows($operation);
            } catch (Throwable $throwable) {
                throw new PrivilegedOperationDeniedException($operation->action, $throwable);
            }

            if (!$allowed) {
                throw new PrivilegedOperationDeniedException($operation->action);
            }
        }

        self::$activeBoundaries[$boundaryKey] = (self::$activeBoundaries[$boundaryKey] ?? 0) + 1;

        try {
            return $callback();
        } finally {
            self::$activeBoundaries[$boundaryKey]--;

            if (self::$activeBoundaries[$boundaryKey] === 0) {
                unset(self::$activeBoundaries[$boundaryKey]);
            }
        }
    }

    /** Test/worker lifecycle helper. */
    public static function reset(): void
    {
        self::$activeBoundaries = [];
    }

}
