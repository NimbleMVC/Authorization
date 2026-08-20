<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Providers;

use krzysztofzylka\DatabaseManager\Cache;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\InsufficientScopeException;
use NimblePHP\Authorization\Exceptions\RateLimitExceededException;
use NimblePHP\Authorization\Providers\APIKeyProvider;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use NimblePHP\Framework\Request;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(APIKeyProvider::class)]
final class APIKeyProviderTest extends TestCase
{

    private PDO $pdo;
    private APIKeyProvider $provider;

    protected function setUp(): void
    {
        Cache::clearAllCache();
        Kernel::$projectPath = dirname(__DIR__, 3);
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.request', new Request(), false);
        Config::$apiKeyRateLimitEnforced = true;

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT NOT NULL,
                key_name TEXT NULL,
                scopes TEXT NULL,
                rate_limit INTEGER NOT NULL DEFAULT 1000,
                auth_epoch INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT NULL,
                revoked_at TEXT NULL,
                last_used_at TEXT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                rate_window_started_at TEXT NULL,
                rate_window_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NULL,
                date_modify TEXT NULL,
                date_created TEXT NULL
            )
            SQL);

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_api_key_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT NOT NULL,
                ip_address TEXT NULL,
                user_agent TEXT NULL,
                accessed_at TEXT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                date_modify TEXT NULL,
                date_created TEXT NULL
            )
            SQL);

        // Work around krzysztofzylka/database-manager's Table::columnList(), which
        // hardcodes `pragma table_info("user")` for sqlite instead of using the
        // actual table name - unrelated to this fix, but it makes Table::find()
        // return an empty column list (and an invalid "SELECT FROM ...") for any
        // table other than one literally named "user". Seed the cache it reads
        // from with the real columns so the provider's Table-backed reads work.
        $this->seedColumnListCache('account_api_keys');
        $this->seedColumnListCache('account_api_key_usage');

        $this->provider = new APIKeyProvider();
    }

    private function seedColumnListCache(string $table): void
    {
        $columns = $this->pdo->query('PRAGMA table_info("' . $table . '")')->fetchAll(PDO::FETCH_ASSOC);
        $describe = array_map(static fn(array $column): array => [
            'Field' => $column['name'],
            'Type' => $column['type'],
            'Null' => $column['notnull'] ? 'NO' : 'YES',
            'Key' => $column['pk'] ? 'PRI' : '',
            'Default' => $column['dflt_value'],
            'Extra' => '',
        ], $columns);

        Cache::saveData('columnList_' . $table, $describe);
    }

    protected function tearDown(): void
    {
        Config::$apiKeyRateLimitEnforced = true;
    }

    public function testValidateTokenReportsScopesAndRateLimit(): void
    {
        $token = $this->provider->generateToken(1, ['scopes' => ['read:posts'], 'rate_limit' => 5]);
        $data = $this->provider->validateToken($token);

        self::assertSame(1, $data['user_id']);
        self::assertSame(['read:posts'], $data['scopes']);
        self::assertSame(5, $data['rate_limit']);
    }

    public function testRateLimitIsEnforcedAtomicallyOnceExhausted(): void
    {
        $token = $this->provider->generateToken(1, [], null);
        $this->pdo->exec('UPDATE account_api_keys SET rate_limit = 2');

        $this->provider->validateToken($token);
        $this->provider->validateToken($token);

        $this->expectException(RateLimitExceededException::class);
        $this->provider->validateToken($token);
    }

    public function testRateLimitReportedByGetRateLimitAfterExhaustion(): void
    {
        $token = $this->provider->generateToken(1, [], null);
        $this->pdo->exec('UPDATE account_api_keys SET rate_limit = 2');

        $this->provider->validateToken($token);
        $this->provider->validateToken($token);

        try {
            $this->provider->validateToken($token);
            self::fail('Third request should have been rate limited');
        } catch (RateLimitExceededException) {
            self::addToAssertionCount(1);
        }

        // getRateLimit() is read-only: it must not throw and must not itself consume a slot.
        $status = $this->provider->getRateLimit($token);
        self::assertSame(2, $status['limit']);
        self::assertSame(2, $status['used']);
        self::assertSame(0, $status['remaining']);
    }

    public function testRateLimitWindowResetsAfterExpiry(): void
    {
        $token = $this->provider->generateToken(1, [], null);
        $this->pdo->exec('UPDATE account_api_keys SET rate_limit = 1');

        $this->provider->validateToken($token);

        try {
            $this->provider->validateToken($token);
            self::fail('Second request within the window should have been rate limited');
        } catch (RateLimitExceededException) {
            self::addToAssertionCount(1);
        }

        // Simulate the hourly window having elapsed.
        $expired = date('Y-m-d H:i:s', time() - 3601);
        $this->pdo->exec("UPDATE account_api_keys SET rate_window_started_at = '{$expired}'");

        $data = $this->provider->validateToken($token);
        self::assertSame(1, $data['user_id']);

        $count = (int)$this->pdo->query('SELECT rate_window_count FROM account_api_keys')->fetchColumn();
        self::assertSame(1, $count);
    }

    public function testRateLimitCanBeDisabledViaConfig(): void
    {
        Config::$apiKeyRateLimitEnforced = false;

        $token = $this->provider->generateToken(1, [], null);
        $this->pdo->exec('UPDATE account_api_keys SET rate_limit = 1');

        $this->provider->validateToken($token);
        $this->provider->validateToken($token);
        $this->provider->validateToken($token);

        self::addToAssertionCount(1);
    }

    public function testHasScopeAndRequireScope(): void
    {
        $tokenData = ['scopes' => ['read:posts', 'write:posts']];

        self::assertTrue($this->provider->hasScope($tokenData, 'read:posts'));
        self::assertFalse($this->provider->hasScope($tokenData, 'delete:posts'));

        $this->provider->requireScope($tokenData, ['read:posts', 'write:posts']);
        self::addToAssertionCount(1);

        try {
            $this->provider->requireScope($tokenData, ['read:posts', 'delete:posts']);
            self::fail('Missing scope should have been rejected');
        } catch (InsufficientScopeException $exception) {
            self::assertStringContainsString('delete:posts', $exception->getMessage());
        }
    }

    public function testUsageLogIsPrunedBeyondRetention(): void
    {
        $token = $this->provider->generateToken(1, [], null);
        $keyHash = hash('sha256', $token);

        $stale = date('Y-m-d H:i:s', time() - 90000); // > 24h retention
        $this->pdo->exec(
            "INSERT INTO account_api_key_usage (user_id, key_hash, ip_address, user_agent, accessed_at) "
            . "VALUES (1, '{$keyHash}', '127.0.0.1', 'stale', '{$stale}')"
        );

        $this->provider->validateToken($token);

        $remaining = $this->pdo->query('SELECT user_agent FROM account_api_key_usage ORDER BY id')
            ->fetchAll(PDO::FETCH_COLUMN);

        self::assertNotContains('stale', $remaining);
    }

}
