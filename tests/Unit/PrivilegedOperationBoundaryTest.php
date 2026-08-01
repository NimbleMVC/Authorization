<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit;

use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Account;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\PrivilegedOperationDeniedException;
use NimblePHP\Authorization\Permission;
use NimblePHP\Authorization\Policies\CallbackPrivilegedOperationPolicy;
use NimblePHP\Authorization\PrivilegedAction;
use NimblePHP\Authorization\PrivilegedOperation;
use NimblePHP\Authorization\Role;
use NimblePHP\Authorization\Services\PrivilegedOperationGate;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use NimblePHP\Framework\Request;
use NimblePHP\Framework\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;

#[CoversClass(PrivilegedOperationGate::class)]
#[CoversClass(PrivilegedOperation::class)]
final class PrivilegedOperationBoundaryTest extends TestCase
{

    private Authorization $authorization;

    protected function setUp(): void
    {
        $_SESSION = [];
        $_COOKIE = [];
        Config::resetPrivilegedOperationPolicy();
        Kernel::$projectPath = dirname(__DIR__, 2);
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.request', new Request(), false);
        Kernel::$serviceContainer->set('kernel.session', new Session(), false);

        $this->authorization = new Authorization();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        $_COOKIE = [];
        Config::resetPrivilegedOperationPolicy();
    }

    public function testDefaultPolicyDeniesImpersonationBeforeAccountLookup(): void
    {
        $this->expectException(PrivilegedOperationDeniedException::class);
        $this->expectExceptionCode(403);

        $this->authorization->authenticateAs(42);
    }

    public function testDefaultPolicyDeniesTokenIssuanceBeforeProviderLookup(): void
    {
        $this->expectException(PrivilegedOperationDeniedException::class);

        $this->authorization->generateToken(42, 'missing-provider');
    }

    public function testDeniedChallengeDoesNotConsumePendingState(): void
    {
        $_SESSION[Config::$challengeSessionKey] = 42;
        $_SESSION[Config::$challengeNameSessionKey] = 'passkey';

        try {
            $this->authorization->completeChallenge();
            self::fail('Challenge completion should have been denied');
        } catch (PrivilegedOperationDeniedException) {
            self::assertSame(42, $_SESSION[Config::$challengeSessionKey]);
            self::assertSame('passkey', $_SESSION[Config::$challengeNameSessionKey]);
            self::assertArrayNotHasKey(Config::$sessionKey, $_SESSION);
        }
    }

    public function testDefaultPolicyDeniesPendingTwoFactorStateWithoutSessionMutation(): void
    {
        try {
            $this->authorization->createPendingTwoFactorState(42, 'totp');
            self::fail('Pending 2FA creation should have been denied');
        } catch (PrivilegedOperationDeniedException) {
            self::assertArrayNotHasKey(Config::$twoFactorSessionKey, $_SESSION);
            self::assertArrayNotHasKey(Config::$twoFactorProviderSessionKey, $_SESSION);
        }
    }

    public function testDefaultPolicyDeniesDirectRbacModels(): void
    {
        $denied = 0;
        $account = new Account(42);
        $role = new Role(1);
        $permission = new Permission(1);

        foreach ([
            static fn(): bool => (new Role())->create('admin'),
            static fn(): bool => (new Permission())->create('users.manage'),
            static fn(): bool => $account->assignRole('admin'),
            static fn(): bool => $account->removeRole('admin'),
            static fn(): bool => $account->setRoles(['admin']),
            static fn(): bool => $account->clearRoles(),
            static fn(): bool => $role->update(['description' => 'changed']),
            static fn(): bool => $role->delete(),
            static fn(): bool => $role->assignToUser(42),
            static fn(): bool => $role->removeFromUser(42),
            static fn(): bool => $role->addPermission(1),
            static fn(): bool => $role->removePermission(1),
            static fn(): bool => $role->setPermissions([1]),
            static fn(): bool => $permission->update(['description' => 'changed']),
            static fn(): bool => $permission->delete(),
            static fn(): bool => $permission->assignToRole(1),
            static fn(): bool => $permission->removeFromRole(1),
        ] as $operation) {
            try {
                $operation();
            } catch (PrivilegedOperationDeniedException) {
                $denied++;
            }
        }

        self::assertSame(17, $denied);
    }

    public function testPolicyReceivesActionTargetContextAndExactEvidence(): void
    {
        $evidence = new stdClass();
        $captured = null;
        Config::setPrivilegedOperationPolicy(new CallbackPrivilegedOperationPolicy(
            static function (PrivilegedOperation $operation) use (&$captured, $evidence): bool {
                $captured = $operation;

                return $operation->action === PrivilegedAction::CREATE_PENDING_TWO_FACTOR
                    && $operation->targetAccountId === 42
                    && $operation->context['provider'] === 'totp'
                    && $operation->evidence === $evidence;
            }
        ));

        $this->authorization->createPendingTwoFactorState(42, 'totp', $evidence);

        self::assertInstanceOf(PrivilegedOperation::class, $captured);
        self::assertNull($captured->actorAccountId);
        self::assertSame(42, $_SESSION[Config::$twoFactorSessionKey]);
        self::assertSame('totp', $_SESSION[Config::$twoFactorProviderSessionKey]);
    }

    public function testPolicyFailureIsFailClosed(): void
    {
        Config::setPrivilegedOperationPolicy(new CallbackPrivilegedOperationPolicy(
            static function (): bool {
                throw new RuntimeException('policy backend failed');
            }
        ));

        try {
            $this->authorization->createPendingTwoFactorState(42, 'totp');
            self::fail('Policy failure should deny the operation');
        } catch (PrivilegedOperationDeniedException $exception) {
            self::assertInstanceOf(RuntimeException::class, $exception->getPrevious());
            self::assertArrayNotHasKey(Config::$twoFactorSessionKey, $_SESSION);
        }
    }

    public function testNestedCallsReuseOnlyTheSameActionAndTargetBoundary(): void
    {
        $policyCalls = 0;
        Config::setPrivilegedOperationPolicy(new CallbackPrivilegedOperationPolicy(
            static function () use (&$policyCalls): bool {
                $policyCalls++;
                return true;
            }
        ));
        $outer = new PrivilegedOperation(PrivilegedAction::MANAGE_RBAC, 1, 42);
        $sameBoundary = new PrivilegedOperation(PrivilegedAction::MANAGE_RBAC, null, 42);
        $differentTarget = new PrivilegedOperation(PrivilegedAction::MANAGE_RBAC, null, 43);

        PrivilegedOperationGate::execute($outer, static function () use ($sameBoundary, $differentTarget): void {
            PrivilegedOperationGate::execute($sameBoundary, static fn(): bool => true);
            PrivilegedOperationGate::execute($differentTarget, static fn(): bool => true);
        });

        self::assertSame(2, $policyCalls);
    }

}
