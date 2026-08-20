<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use krzysztofzylka\DatabaseManager\Cache;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\TOTPProvider;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use NimblePHP\Framework\Request;
use NimblePHP\Framework\Session;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * AUT-H07: enableTwoFactorAuth() must never return a QR code image/URL that
 * would leak the TOTP secret to a third-party rendering service.
 */
#[CoversClass(Authorization::class)]
final class AuthorizationTwoFactorEnrollmentTest extends TestCase
{
    private PDO $pdo;
    private Authorization $authorization;

    protected function setUp(): void
    {
        $_SESSION = [];
        $_COOKIE = [];
        Cache::clearAllCache();
        Kernel::$projectPath = dirname(__DIR__, 2);
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.request', new Request(), false);
        Kernel::$serviceContainer->set('kernel.session', new Session(), false);

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);

        // "user" sidesteps a Table::columnList() bug in krzysztofzylka/database-manager
        // (its sqlite branch hardcodes `pragma table_info("user")`), same workaround
        // already used by AuthorizationAccountStateTest.
        Config::$tableName = 'user';
        Config::$columns = [
            'id' => 'id', 'username' => 'username', 'email' => 'email',
            'password' => 'password', 'active' => 'active',
            'auth_epoch' => 'auth_epoch', 'created_at' => 'date_created',
        ];
        Config::$sessionKey = 'account_id';
        Config::$authEpochSessionKey = 'account_auth_epoch';
        Config::$recoveryCodeTableName = 'account_two_factor_recovery_codes';

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                auth_epoch INTEGER NOT NULL DEFAULT 0,
                account_two_factor_secret TEXT NULL,
                account_two_factor_provider TEXT NULL,
                date_created TEXT NOT NULL
            )
            SQL);
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_two_factor_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used_at TEXT NULL,
                expires_at TEXT NOT NULL,
                date_modify TEXT NULL,
                date_created TEXT NULL
            )
            SQL);

        $this->pdo->exec(
            "INSERT INTO user (id, username, email, password, active, auth_epoch, date_created) "
            . "VALUES (1, 'alice', 'alice@example.com', 'hash', 1, 0, '2026-01-01 00:00:00')"
        );

        $_SESSION[Config::$sessionKey] = 1;
        $_SESSION[Config::$authEpochSessionKey] = 0;

        $this->authorization = new Authorization();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        $_COOKIE = [];
        Config::$tableName = 'accounts';
        Config::$columns = [
            'id' => 'id', 'username' => 'username', 'email' => 'email',
            'password' => 'password', 'active' => 'active',
            'auth_epoch' => 'auth_epoch', 'created_at' => 'date_created',
        ];
        Config::$sessionKey = 'account_id';
        Config::$authEpochSessionKey = 'account_auth_epoch';
        Config::$recoveryCodeTableName = 'account_two_factor_recovery_codes';
    }

    public function testEnrollmentNeverReturnsAQrCodeImageOrUrl(): void
    {
        $result = $this->authorization->enableTwoFactorAuth(new TOTPProvider());

        self::assertSame(['secret', 'provider', 'recovery_codes'], array_keys($result));
        self::assertArrayNotHasKey('qr_code', $result);
        self::assertCount(10, $result['recovery_codes']);
    }
}
