<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Interfaces;

interface RecoveryCodeStorage
{
    /**
     * @param array<int, array{code_hash: string, expires_at: string}> $codes
     */
    public function replaceForAccount(int $accountId, array $codes): void;

    /**
     * @return array<int, array{id: int, code_hash: string}>
     */
    public function findActiveForAccount(int $accountId, string $now): array;

    public function consume(int $id, int $accountId, string $usedAt): bool;

    public function deleteForAccount(int $accountId): void;
}
