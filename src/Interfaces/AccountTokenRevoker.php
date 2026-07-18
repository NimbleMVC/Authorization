<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Interfaces;

/** Token providers that can revoke every credential belonging to an account. */
interface AccountTokenRevoker
{
    public function revokeAllForAccount(int $accountId): bool;
}
