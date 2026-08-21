<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit;

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\RateLimiter;
use NimblePHP\Authorization\Storages\SessionRateLimiterStorage;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use NimblePHP\Framework\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RateLimiter::class)]
final class RateLimiterTest extends TestCase
{
    private RateLimiter $limiter;

    protected function setUp(): void
    {
        $_SESSION = [];
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.session', new Session(), false);

        Config::$rateLimitMaxAttempts = 5;
        Config::$rateLimitLockoutDuration = 900;
        Config::$rateLimitTrackIp = false;
        Config::setRateLimiterStorage(new SessionRateLimiterStorage());

        $this->limiter = new RateLimiter();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        Config::$rateLimitMaxAttempts = 5;
        Config::$rateLimitLockoutDuration = 900;
        Config::$rateLimitTrackIp = false;
        Config::setRateLimiterStorage(new SessionRateLimiterStorage());
    }

    public function testIdentifierIsNotLimitedBelowTheDefaultThreshold(): void
    {
        for ($i = 0; $i < 4; $i++) {
            $this->limiter->recordFailedAttempt('alice@example.com');
        }

        self::assertFalse($this->limiter->isRateLimited('alice@example.com'));
        self::assertSame(1, $this->limiter->getRemainingAttempts('alice@example.com'));
    }

    public function testIdentifierIsLockedAtTheDefaultThreshold(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->recordFailedAttempt('alice@example.com');
        }

        self::assertTrue($this->limiter->isRateLimited('alice@example.com'));
        self::assertSame(0, $this->limiter->getRemainingAttempts('alice@example.com'));
        self::assertGreaterThan(0, $this->limiter->getLockoutTimeRemaining('alice@example.com'));
    }

    public function testClearAttemptsRemovesTheLockout(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->recordFailedAttempt('alice@example.com');
        }

        self::assertTrue($this->limiter->isRateLimited('alice@example.com'));

        $this->limiter->clearAttempts('alice@example.com');

        self::assertFalse($this->limiter->isRateLimited('alice@example.com'));
    }

    public function testPerCallMaxAttemptsAndLockoutDurationOverrideConfigDefaults(): void
    {
        // AUT-M01 relies on this: a caller (2FA) can use tighter thresholds
        // than the Config defaults used for login, on the same RateLimiter.
        $this->limiter->recordFailedAttempt('2fa:1', maxAttempts: 2, lockoutDuration: 60);
        self::assertFalse($this->limiter->isRateLimited('2fa:1'));

        $this->limiter->recordFailedAttempt('2fa:1', maxAttempts: 2, lockoutDuration: 60);
        self::assertTrue($this->limiter->isRateLimited('2fa:1'));
        self::assertLessThanOrEqual(60, $this->limiter->getLockoutTimeRemaining('2fa:1'));

        // Config defaults (max 5) are untouched by the override.
        self::assertFalse($this->limiter->isRateLimited('alice@example.com'));
    }

    public function testIpTrackingLocksOutBothTheIdentifierAndItsSharedIp(): void
    {
        Config::$rateLimitTrackIp = true;
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5';

        for ($i = 0; $i < 5; $i++) {
            $this->limiter->recordFailedAttempt('alice@example.com');
        }

        self::assertTrue($this->limiter->isRateLimited('alice@example.com'));
        // isRateLimited() unions the identifier key with the "ip:<addr>" key,
        // so another identifier from the same (now-locked) IP is blocked too.
        self::assertTrue($this->limiter->isRateLimited('bob@example.com'));

        unset($_SERVER['REMOTE_ADDR']);
    }
}
