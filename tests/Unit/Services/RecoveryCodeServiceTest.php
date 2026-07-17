<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Services;

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\RecoveryCodeStorage;
use NimblePHP\Authorization\Providers\TOTPProvider;
use NimblePHP\Authorization\Services\RecoveryCodeService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeServiceTest extends TestCase
{
    private InMemoryRecoveryCodeStorage $storage;

    private RecoveryCodeService $service;

    private int $originalLifetime;

    protected function setUp(): void
    {
        $this->originalLifetime = Config::$recoveryCodeLifetime;
        Config::$recoveryCodeLifetime = 3600;
        $this->storage = new InMemoryRecoveryCodeStorage();
        $this->service = new RecoveryCodeService($this->storage, PASSWORD_BCRYPT, ['cost' => 4]);
    }

    protected function tearDown(): void
    {
        Config::$recoveryCodeLifetime = $this->originalLifetime;
    }

    public function testStoresOnlyCostlyHashesOfGeneratedCodes(): void
    {
        $codes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');

        self::assertCount(10, $codes);
        self::assertCount(10, $this->storage->codes);

        foreach ($this->storage->codes as $index => $storedCode) {
            self::assertNotSame($codes[$index], $storedCode['code_hash']);
            self::assertTrue(password_verify($codes[$index], $storedCode['code_hash']));
        }
    }

    public function testValidRecoveryCodeCanBeConsumedOnlyOnce(): void
    {
        $codes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');

        self::assertTrue($this->service->consume(42, $codes[0]));
        self::assertFalse($this->service->consume(42, $codes[0]));
    }

    public function testRecoveryCodeIsBoundToTheAccount(): void
    {
        $codes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');

        self::assertFalse($this->service->consume(7, $codes[0]));
        self::assertTrue($this->service->consume(42, $codes[0]));
    }

    public function testArbitraryWellFormattedCodeIsRejected(): void
    {
        $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');

        self::assertFalse($this->service->consume(42, 'AAAA-AAAA'));
    }

    public function testGeneratingNewSetInvalidatesPreviousCodes(): void
    {
        $oldCodes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');
        $newCodes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');

        self::assertFalse($this->service->consume(42, $oldCodes[0]));
        self::assertTrue($this->service->consume(42, $newCodes[0]));
    }

    public function testExpiredRecoveryCodeIsRejected(): void
    {
        $codes = $this->service->generateForAccount(42, new TOTPProvider(), 'unused-secret');
        $this->storage->codes[0]['expires_at'] = '2000-01-01 00:00:00';

        self::assertFalse($this->service->consume(42, $codes[0]));
    }
}

final class InMemoryRecoveryCodeStorage implements RecoveryCodeStorage
{
    /**
     * @var array<int, array{id: int, account_id: int, code_hash: string, expires_at: string, used_at: ?string}>
     */
    public array $codes = [];

    public function replaceForAccount(int $accountId, array $codes): void
    {
        $this->deleteForAccount($accountId);

        foreach ($codes as $code) {
            $this->codes[] = [
                'id' => count($this->codes) + 1,
                'account_id' => $accountId,
                'code_hash' => $code['code_hash'],
                'expires_at' => $code['expires_at'],
                'used_at' => null,
            ];
        }
    }

    public function findActiveForAccount(int $accountId, string $now): array
    {
        return array_values(array_map(
            static fn (array $code): array => [
                'id' => $code['id'],
                'code_hash' => $code['code_hash'],
            ],
            array_filter(
                $this->codes,
                static fn (array $code): bool => $code['account_id'] === $accountId
                    && $code['used_at'] === null
                    && $code['expires_at'] > $now
            )
        ));
    }

    public function consume(int $id, int $accountId, string $usedAt): bool
    {
        foreach ($this->codes as &$code) {
            if (
                $code['id'] === $id
                && $code['account_id'] === $accountId
                && $code['used_at'] === null
                && $code['expires_at'] > $usedAt
            ) {
                $code['used_at'] = $usedAt;

                return true;
            }
        }

        return false;
    }

    public function deleteForAccount(int $accountId): void
    {
        $this->codes = array_values(array_filter(
            $this->codes,
            static fn (array $code): bool => $code['account_id'] !== $accountId
        ));
    }
}
