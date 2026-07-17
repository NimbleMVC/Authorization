<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Services;

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\RecoveryCodeStorage;
use NimblePHP\Authorization\Interfaces\TwoFactorProvider;
use NimblePHP\Authorization\Storages\DatabaseRecoveryCodeStorage;
use RuntimeException;
use UnexpectedValueException;

final class RecoveryCodeService
{
    private RecoveryCodeStorage $storage;

    /** @var string|int|null */
    private string|int|null $hashAlgorithm;

    /** @var array<string, int> */
    private array $hashOptions;

    /**
     * Hash parameters are injectable so tests can use a lower cost. Production
     * callers should keep the PASSWORD_DEFAULT defaults.
     *
     * @param array<string, int> $hashOptions
     */
    public function __construct(
        ?RecoveryCodeStorage $storage = null,
        string|int|null $hashAlgorithm = PASSWORD_DEFAULT,
        array $hashOptions = []
    ) {
        $this->storage = $storage ?? new DatabaseRecoveryCodeStorage();
        $this->hashAlgorithm = $hashAlgorithm;
        $this->hashOptions = $hashOptions;
    }

    /**
     * Generate a fresh recovery-code set and invalidate the previous set.
     * Plain-text codes are returned exactly once and are never persisted.
     *
     * @return array<int, string>
     */
    public function generateForAccount(
        int $accountId,
        TwoFactorProvider $provider,
        string $secret
    ): array {
        return $this->replaceForAccount($accountId, $provider->getRecoveryCodes($secret));
    }

    /**
     * Replace an account's recovery-code set with newly generated plain-text codes.
     *
     * @param array<int, string> $plainTextCodes
     * @return array<int, string> Canonically formatted codes for one-time display
     */
    public function replaceForAccount(int $accountId, array $plainTextCodes): array
    {
        $codes = array_values(array_unique(array_map(
            fn (string $code): string => $this->normalize($code) ?? '',
            $plainTextCodes
        )));

        if ($codes === [] || in_array('', $codes, true)) {
            throw new UnexpectedValueException('The two-factor provider did not generate valid recovery codes');
        }

        $expiresAt = date('Y-m-d H:i:s', time() + Config::$recoveryCodeLifetime);
        $storedCodes = [];

        foreach ($codes as $code) {
            $hash = password_hash($code, $this->hashAlgorithm, $this->hashOptions);

            if ($hash === false) {
                throw new RuntimeException('Unable to hash a recovery code');
            }

            $storedCodes[] = [
                'code_hash' => $hash,
                'expires_at' => $expiresAt,
            ];
        }

        $this->storage->replaceForAccount($accountId, $storedCodes);

        return $codes;
    }

    /**
     * Verify and atomically consume one recovery code.
     */
    public function consume(int $accountId, string $code): bool
    {
        $normalizedCode = $this->normalize($code);

        if ($normalizedCode === null) {
            return false;
        }

        $now = date('Y-m-d H:i:s');

        foreach ($this->storage->findActiveForAccount($accountId, $now) as $storedCode) {
            if (!password_verify($normalizedCode, $storedCode['code_hash'])) {
                continue;
            }

            return $this->storage->consume((int)$storedCode['id'], $accountId, $now);
        }

        return false;
    }

    public function invalidateForAccount(int $accountId): void
    {
        $this->storage->deleteForAccount($accountId);
    }

    private function normalize(string $code): ?string
    {
        $normalizedCode = strtoupper(trim($code));

        return preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $normalizedCode) === 1
            ? $normalizedCode
            : null;
    }
}
