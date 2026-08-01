<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Providers;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Cache;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Providers\JWTProvider;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JWTProvider::class)]
final class JWTProviderTest extends TestCase
{

    private const SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    private PDO $pdo;
    private JWTProvider $provider;

    protected function setUp(): void
    {
        Cache::clearAllCache();
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_token_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_jti TEXT NOT NULL,
                token_type TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                date_created TEXT NULL,
                date_modify TEXT NULL
            )
            SQL);

        $this->provider = new JWTProvider(
            self::SECRET,
            defaultExpirationTime: 600,
            issuer: 'authorization.test',
            audience: 'api.test',
            maximumLifetime: 3600,
        );
    }

    public function testCallerCannotSupplyProtectedClaims(): void
    {
        $values = [
            'user_id' => 999,
            'sub' => '999',
            'iat' => 1,
            'nbf' => 1,
            'exp' => PHP_INT_MAX,
            'jti' => str_repeat('f', 32),
            'iss' => 'attacker',
            'aud' => 'attacker',
        ];

        foreach ($values as $claim => $value) {
            try {
                $this->provider->generateToken(1, [$claim => $value]);
                self::fail(sprintf('Protected claim %s should have been rejected', $claim));
            } catch (InvalidArgumentException $exception) {
                self::assertStringContainsString($claim, $exception->getMessage());
            }
        }
    }

    public function testSystemClaimsCannotBeReplacedAndCustomClaimsRemainAvailable(): void
    {
        $before = time();
        $payload = $this->decodePayload($this->provider->generateToken(7, ['scope' => 'read'], 300));

        self::assertSame(7, $payload['user_id']);
        self::assertSame('7', $payload['sub']);
        self::assertSame('read', $payload['scope']);
        self::assertGreaterThanOrEqual($before, $payload['iat']);
        self::assertSame($payload['iat'], $payload['nbf']);
        self::assertSame(300, $payload['exp'] - $payload['iat']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $payload['jti']);
        self::assertSame('authorization.test', $payload['iss']);
        self::assertSame('api.test', $payload['aud']);
    }

    public function testValidationRequiresIdentityTimeExpirationAndRevocationClaims(): void
    {
        foreach (['user_id', 'iat', 'exp', 'jti'] as $claim) {
            $payload = $this->validPayload();
            unset($payload[$claim]);
            $this->assertTokenRejected($this->forgeToken($payload));
        }

        $payload = $this->validPayload();
        unset($payload['nbf']);
        self::assertSame(1, $this->provider->validateToken($this->forgeToken($payload))['user_id']);
    }

    public function testValidationRejectsInvalidClaimTypesAndRelationships(): void
    {
        $cases = [
            ['user_id', '1'],
            ['user_id', 0],
            ['iat', '1'],
            ['exp', 1.5],
            ['jti', 'short'],
            ['sub', '2'],
            ['nbf', '1'],
        ];

        foreach ($cases as [$claim, $value]) {
            $payload = $this->validPayload();
            $payload[$claim] = $value;
            $this->assertTokenRejected($this->forgeToken($payload));
        }

        $payload = $this->validPayload();
        $payload['exp'] = $payload['iat'];
        $this->assertTokenRejected($this->forgeToken($payload));
    }

    public function testGenerationAndValidationEnforceMaximumLifetime(): void
    {
        foreach ([0, -1, 3601] as $lifetime) {
            try {
                $this->provider->generateToken(1, [], $lifetime);
                self::fail('Out-of-range JWT lifetime should have been rejected');
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }

        $payload = $this->validPayload();
        $payload['exp'] = $payload['iat'] + 3601;
        $this->assertTokenRejected($this->forgeToken($payload));
    }

    public function testValidationEnforcesIssuerAudienceAndHeader(): void
    {
        $payload = $this->validPayload();
        $payload['iss'] = 'other-issuer';
        $this->assertTokenRejected($this->forgeToken($payload));

        $payload = $this->validPayload();
        $payload['aud'] = 'other-audience';
        $this->assertTokenRejected($this->forgeToken($payload));

        $this->assertTokenRejected($this->forgeToken($this->validPayload(), ['alg' => 'none', 'typ' => 'JWT']));
        $this->assertTokenRejected($this->forgeToken($this->validPayload(), ['alg' => 'HS256', 'typ' => 'OTHER']));

        $withoutBinding = new JWTProvider(self::SECRET, maximumLifetime: 3600);
        $this->assertTokenRejected($this->forgeToken($this->validPayload()), $withoutBinding);

        $unboundPayload = $this->validPayload();
        unset($unboundPayload['iss'], $unboundPayload['aud']);
        self::assertSame(1, $withoutBinding->validateToken($this->forgeToken($unboundPayload))['user_id']);
    }

    public function testValidationRejectsFutureAndExpiredTokens(): void
    {
        $payload = $this->validPayload();
        $payload['iat'] = time() + 60;
        $payload['nbf'] = $payload['iat'];
        $payload['exp'] = $payload['iat'] + 300;
        $this->assertTokenRejected($this->forgeToken($payload));

        $payload = $this->validPayload();
        $payload['nbf'] = time() + 60;
        $this->assertTokenRejected($this->forgeToken($payload));

        $payload = $this->validPayload();
        $payload['iat'] = time() - 600;
        $payload['nbf'] = $payload['iat'];
        $payload['exp'] = time() - 1;
        $this->assertTokenRejected($this->forgeToken($payload));
    }

    public function testRefreshRotatesIdentifierAndRevokesPreviousToken(): void
    {
        $oldToken = $this->provider->generateToken(7, ['scope' => 'read', 'auth_epoch' => 3]);
        $oldPayload = $this->provider->validateToken($oldToken);

        $newToken = $this->provider->refreshToken($oldToken, 900);
        $newPayload = $this->provider->validateToken($newToken);

        self::assertNotSame($oldToken, $newToken);
        self::assertNotSame($oldPayload['jti'], $newPayload['jti']);
        self::assertSame(7, $newPayload['user_id']);
        self::assertSame('read', $newPayload['scope']);
        self::assertSame(3, $newPayload['auth_epoch']);
        self::assertSame(1, (int)$this->pdo->query('SELECT COUNT(*) FROM account_token_blacklist')->fetchColumn());
        $this->assertTokenRejected($oldToken);
    }

    /** @return array<string, mixed> */
    private function validPayload(): array
    {
        $now = time() - 10;

        return [
            'user_id' => 1,
            'sub' => '1',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + 600,
            'jti' => str_repeat('a', 32),
            'iss' => 'authorization.test',
            'aud' => 'api.test',
        ];
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $header
     */
    private function forgeToken(array $payload, array $header = ['alg' => 'HS256', 'typ' => 'JWT']): string
    {
        $headerEncoded = $this->base64UrlEncode((string)json_encode($header, JSON_THROW_ON_ERROR));
        $payloadEncoded = $this->base64UrlEncode((string)json_encode($payload, JSON_THROW_ON_ERROR));
        $signature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, self::SECRET, true);

        return $headerEncoded . '.' . $payloadEncoded . '.' . $this->base64UrlEncode($signature);
    }

    /** @return array<string, mixed> */
    private function decodePayload(string $token): array
    {
        $parts = explode('.', $token);
        $encoded = strtr($parts[1], '-_', '+/');
        $encoded .= str_repeat('=', (4 - strlen($encoded) % 4) % 4);

        return json_decode((string)base64_decode($encoded, true), true, 512, JSON_THROW_ON_ERROR);
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function assertTokenRejected(string $token, ?JWTProvider $provider = null): void
    {
        try {
            ($provider ?? $this->provider)->validateToken($token);
            self::fail('JWT should have been rejected');
        } catch (\Exception) {
            self::addToAssertionCount(1);
        }
    }

}
