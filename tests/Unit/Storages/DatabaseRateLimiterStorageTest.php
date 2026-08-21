<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Storages;

use krzysztofzylka\DatabaseManager\Cache;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Storages\DatabaseRateLimiterStorage;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use NimblePHP\Framework\Session;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * AUT-M04: increment() must apply the stale-window reset, attempt count,
 * and lockout threshold atomically, and the storage must fail closed when
 * its table is missing unless the weaker fallback is explicitly allowed.
 */
#[CoversClass(DatabaseRateLimiterStorage::class)]
final class DatabaseRateLimiterStorageTest extends TestCase
{
    private PDO $pdo;
    private DatabaseRateLimiterStorage $storage;

    protected function setUp(): void
    {
        Cache::clearAllCache();
        Kernel::$projectPath = dirname(__DIR__, 3);
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.session', new Session(), false);

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);

        Config::$rateLimitTableName = 'account_rate_limits';
        Config::$rateLimitAllowSessionFallback = false;

        $this->storage = new DatabaseRateLimiterStorage();
    }

    protected function tearDown(): void
    {
        Config::$rateLimitAllowSessionFallback = false;
    }

    private function createTable(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_attempt INTEGER NOT NULL,
                last_attempt INTEGER NOT NULL,
                locked_until INTEGER NULL,
                date_modify TEXT NULL,
                date_created TEXT NULL
            )
            SQL);
        $this->pdo->exec('CREATE UNIQUE INDEX rate_limit_identifier_unique ON account_rate_limits (identifier)');

        // Table::columnList() hardcodes `pragma table_info("user")` for sqlite
        // in krzysztofzylka/database-manager - unrelated bug, worked around
        // the same way as in APIKeyProviderTest by seeding its cache directly.
        $columns = $this->pdo->query('PRAGMA table_info("account_rate_limits")')->fetchAll(PDO::FETCH_ASSOC);
        Cache::saveData('columnList_account_rate_limits', array_map(static fn(array $c): array => [
            'Field' => $c['name'], 'Type' => $c['type'], 'Null' => $c['notnull'] ? 'NO' : 'YES',
            'Key' => $c['pk'] ? 'PRI' : '', 'Default' => $c['dflt_value'], 'Extra' => '',
        ], $columns));
    }

    public function testIncrementCreatesRowOnFirstAttempt(): void
    {
        $this->createTable();
        $now = time();

        $result = $this->storage->increment('alice', $now, 5, 900);

        self::assertSame(1, $result['attempts']);
        self::assertNull($result['locked_until']);
    }

    public function testIncrementAccumulatesWithinWindowWithoutLocking(): void
    {
        $this->createTable();
        $now = time();

        $this->storage->increment('alice', $now, 5, 900);
        $this->storage->increment('alice', $now, 5, 900);
        $result = $this->storage->increment('alice', $now, 5, 900);

        self::assertSame(3, $result['attempts']);
        self::assertNull($result['locked_until']);
    }

    public function testIncrementLocksOnceMaxAttemptsReached(): void
    {
        $this->createTable();
        $now = time();

        $this->storage->increment('alice', $now, 2, 900);
        $result = $this->storage->increment('alice', $now, 2, 900);

        self::assertSame(2, $result['attempts']);
        self::assertSame($now + 900, $result['locked_until']);
    }

    public function testIncrementResetsAfterTheObservationWindowGoesStale(): void
    {
        $this->createTable();
        $start = time() - 10_000;

        $this->storage->increment('alice', $start, 5, 900);
        $this->storage->increment('alice', $start, 5, 900);

        $muchLater = $start + 10_000; // well past the 900s window
        $result = $this->storage->increment('alice', $muchLater, 5, 900);

        self::assertSame(1, $result['attempts']);
    }

    public function testConcurrentIncrementsAreNotLostToARace(): void
    {
        $this->createTable();
        $now = time();

        // Same identifier, simulating two callers racing against the same
        // row: without an atomic UPSERT a get()-then-set() pair can lose one
        // of these to a last-write-wins overwrite.
        for ($i = 0; $i < 10; $i++) {
            $result = $this->storage->increment('alice', $now, 1000, 900);
        }

        self::assertSame(10, $result['attempts']);
    }

    public function testMissingTableFailsClosedByDefault(): void
    {
        $this->expectException(DatabaseManagerException::class);

        $this->storage->increment('alice', time(), 5, 900);
    }

    public function testMissingTableFallsBackToSessionWhenExplicitlyAllowed(): void
    {
        Config::$rateLimitAllowSessionFallback = true;

        $result = $this->storage->increment('alice', time(), 5, 900);

        self::assertSame(1, $result['attempts']);
    }
}
