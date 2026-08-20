<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use krzysztofzylka\DatabaseManager\Cache;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\RateLimitExceededException;
use NimblePHP\Authorization\Exceptions\TwoFactorException;
use NimblePHP\Authorization\Providers\TOTPProvider;
use NimblePHP\Authorization\Storages\SessionRateLimiterStorage;
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
 * AUT-M01: verifyTwoFactorCode() must expire a stale pending challenge and
 * lock out an account after too many wrong codes, independently of the
 * login rate limiter (which a correct password already clears).
 */
#[CoversClass(Authorization::class)]
final class AuthorizationTwoFactorRateLimitTest extends TestCase
{
    private const ACCOUNT_ID = 1;

    private PDO $pdo;
    private Authorization $authorization;
    private TOTPProvider $totp;
    private string $secret;

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
        // (its sqlite branch hardcodes `pragma table_info("user")`).
        Config::$tableName = 'user';
        Config::$columns = [
            'id' => 'id', 'username' => 'username', 'email' => 'email',
            'password' => 'password', 'active' => 'active',
            'auth_epoch' => 'auth_epoch', 'created_at' => 'date_created',
        ];
        Config::$sessionKey = 'account_id';
        Config::$authEpochSessionKey = 'account_auth_epoch';
        Config::$recoveryCodeTableName = 'account_two_factor_recovery_codes';
        Config::$rateLimitEnabled = true;
        Config::$rateLimitTrackIp = false;
        Config::$twoFactorMaxAttempts = 2;
        Config::$twoFactorLockoutDuration = 300;
        Config::$twoFactorChallengeLifetime = 300;
        // Session-backed limiter: no schema to seed, and its "resets if the
        // attacker drops the cookie" weakness is irrelevant to what this test
        // is checking (Authorization's TTL/attempt-limit wiring), unlike the
        // persistent DatabaseRateLimiterStorage used by default in production.
        Config::setRateLimiterStorage(new SessionRateLimiterStorage());

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

        $this->totp = new TOTPProvider();
        $this->secret = $this->totp->generateSecret();
        Config::registerTwoFactorProvider('totp', $this->totp);

        $this->pdo->exec(
            "INSERT INTO user (id, username, email, password, active, auth_epoch, "
            . "account_two_factor_secret, account_two_factor_provider, date_created) "
            . "VALUES (" . self::ACCOUNT_ID . ", 'alice', 'alice@example.com', 'hash', 1, 0, "
            . "'{$this->secret}', 'totp', '2026-01-01 00:00:00')"
        );

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
        Config::$rateLimitTrackIp = false;
        Config::$twoFactorMaxAttempts = 5;
        Config::$twoFactorLockoutDuration = 300;
        Config::$twoFactorChallengeLifetime = 300;
        Config::setRateLimiterStorage(new SessionRateLimiterStorage());
    }

    public function testExpiredChallengeIsRejectedAndCleared(): void
    {
        $this->startChallenge(time() - Config::$twoFactorChallengeLifetime - 1);

        $this->expectException(TwoFactorException::class);

        try {
            $this->authorization->verifyTwoFactorCode($this->totp->generateCode($this->secret));
        } finally {
            self::assertArrayNotHasKey(Config::$twoFactorSessionKey, $_SESSION);
        }
    }

    public function testAccountIsLockedAfterMaxWrongAttemptsAndSurvivesANewChallenge(): void
    {
        $this->startChallenge(time());

        for ($i = 0; $i < Config::$twoFactorMaxAttempts; $i++) {
            try {
                $this->authorization->verifyTwoFactorCode('000000');
                self::fail('Wrong code should have been rejected');
            } catch (TwoFactorException) {
                self::addToAssertionCount(1);
            }
        }

        // The challenge itself was cleared once the limit was crossed.
        self::assertArrayNotHasKey(Config::$twoFactorSessionKey, $_SESSION);

        // A fresh challenge for the SAME account (as a correct-password relogin
        // would create) must still be locked out - the account-level counter is
        // independent of both the pending-challenge state and the login rate
        // limiter (which a correct password already clears).
        $this->startChallenge(time());

        $this->expectException(RateLimitExceededException::class);
        $this->authorization->verifyTwoFactorCode($this->totp->generateCode($this->secret));
    }

    public function testSuccessfulVerificationResetsTheAttemptCounter(): void
    {
        $this->startChallenge(time());

        try {
            $this->authorization->verifyTwoFactorCode('000000');
            self::fail('Wrong code should have been rejected');
        } catch (TwoFactorException) {
            self::addToAssertionCount(1);
        }

        self::assertTrue($this->authorization->verifyTwoFactorCode($this->totp->generateCode($this->secret)));

        // A new challenge starts with a clean slate: one more wrong guess must
        // not immediately hit the (maxAttempts = 2) lockout.
        $this->startChallenge(time());

        try {
            $this->authorization->verifyTwoFactorCode('000000');
            self::fail('Wrong code should have been rejected');
        } catch (TwoFactorException) {
            self::addToAssertionCount(1);
        }

        self::assertTrue(isset($_SESSION[Config::$twoFactorSessionKey]));
    }

    private function startChallenge(int $startedAt): void
    {
        $_SESSION[Config::$twoFactorSessionKey] = self::ACCOUNT_ID;
        $_SESSION[Config::$twoFactorProviderSessionKey] = 'totp';
        $_SESSION[Config::$twoFactorChallengeStartedAtSessionKey] = $startedAt;
    }
}
