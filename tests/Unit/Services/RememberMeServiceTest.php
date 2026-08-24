<?php

declare(strict_types=1);

// PHP's CLI SAPI never populates headers_list() for setcookie() calls (no
// real HTTP transport to hold them), so RememberMeService's real
// setcookie()/unset cookie can't be observed from a CLI test that way.
// Shadow the global setcookie() with a namespaced one PHP resolves first for
// unqualified calls made from within RememberMeService's own namespace -
// this is a test-only interception, production code is untouched.
namespace NimblePHP\Authorization\Services {
    if (!function_exists(__NAMESPACE__ . '\\setcookie')) {
        function setcookie(string $name, string $value = '', array $options = []): bool
        {
            $GLOBALS['__test_intercepted_cookies'][$name] = $value;

            return true;
        }
    }
}

namespace NimblePHP\Authorization\Tests\Unit\Services {

    use krzysztofzylka\DatabaseManager\Cache;
    use krzysztofzylka\DatabaseManager\DatabaseConnect;
    use krzysztofzylka\DatabaseManager\DatabaseManager;
    use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
    use NimblePHP\Authorization\Config;
    use NimblePHP\Authorization\Services\RememberMeService;
    use NimblePHP\Framework\Container\ServiceContainer;
    use NimblePHP\Framework\Cookie;
    use NimblePHP\Framework\Kernel;
    use NimblePHP\Framework\Middleware\MiddlewareManager;
    use PDO;
    use PHPUnit\Framework\Attributes\CoversClass;
    use PHPUnit\Framework\TestCase;
    use ReflectionClass;

    /**
     * AUT-M05: rotation must consume the old token atomically and detect
     * reuse of an already-rotated-away token as theft, instead of the
     * previous read-then-delete pair two concurrent requests could both pass.
     */
    #[CoversClass(RememberMeService::class)]
    final class RememberMeServiceTest extends TestCase
    {
        private const ACCOUNT_ID = 1;

        private PDO $pdo;
        private RememberMeService $service;

        protected function setUp(): void
        {
            $_COOKIE = [];
            $GLOBALS['__test_intercepted_cookies'] = [];
            Cache::clearAllCache();
            Kernel::$projectPath = dirname(__DIR__, 3);
            Kernel::$middlewareManager = new MiddlewareManager();
            Kernel::$serviceContainer = ServiceContainer::getInstance();
            Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);

            $this->pdo = new PDO('sqlite::memory:');
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            DatabaseManager::$connection = DatabaseConnect::create()
                ->setType(DatabaseType::sqlite)
                ->setConnection($this->pdo);

            Config::$rememberMeTableName = 'account_remember_tokens';
            Config::$rememberMeLifetime = 2_592_000;
            Config::$rememberMeRotationInterval = 300;

            $this->pdo->exec(<<<'SQL'
                CREATE TABLE account_remember_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    selector TEXT NOT NULL,
                    validator_hash TEXT NOT NULL,
                    family_id TEXT NULL,
                    used_at TEXT NULL,
                    date_expired TEXT NOT NULL,
                    date_modify TEXT NULL,
                    date_created TEXT NULL
                )
                SQL);

            // Table::columnList() hardcodes `pragma table_info("user")` for
            // sqlite in krzysztofzylka/database-manager - unrelated bug,
            // worked around by seeding its cache directly (same as
            // APIKeyProviderTest and others).
            $columns = $this->pdo->query('PRAGMA table_info("account_remember_tokens")')->fetchAll(PDO::FETCH_ASSOC);
            Cache::saveData('columnList_account_remember_tokens', array_map(static fn(array $c): array => [
                'Field' => $c['name'], 'Type' => $c['type'], 'Null' => $c['notnull'] ? 'NO' : 'YES',
                'Key' => $c['pk'] ? 'PRI' : '', 'Default' => $c['dflt_value'], 'Extra' => '',
            ], $columns));

            $this->service = new RememberMeService();
        }

        protected function tearDown(): void
        {
            $_COOKIE = [];
            $GLOBALS['__test_intercepted_cookies'] = [];
            Config::$rememberMeTableName = 'account_remember_tokens';
            Config::$rememberMeLifetime = 2_592_000;
            Config::$rememberMeRotationInterval = 300;
        }

        public function testCreateAndCheckRoundTrip(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $this->applyInterceptedCookie();

            self::assertSame(self::ACCOUNT_ID, $this->service->check());
        }

        public function testWithinTheThrottleWindowTheSameTokenStaysValidAndUnconsumed(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $this->applyInterceptedCookie();
            $cookieBefore = $_COOKIE[Config::$rememberMeCookieName];

            self::assertSame(self::ACCOUNT_ID, $this->service->check());

            // No rotation happened: used_at is still NULL and the cookie the
            // caller already has keeps working for a second request.
            $row = $this->pdo->query('SELECT used_at FROM account_remember_tokens')->fetch(PDO::FETCH_ASSOC);
            self::assertNull($row['used_at']);

            $_COOKIE[Config::$rememberMeCookieName] = $cookieBefore;
            self::assertSame(self::ACCOUNT_ID, $this->service->check());
        }

        public function testRotationPastTheThrottleWindowConsumesTheOldTokenAndKeepsTheFamily(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $this->applyInterceptedCookie();
            $oldSelector = explode(':', $_COOKIE[Config::$rememberMeCookieName], 2)[0];
            $oldFamily = $this->pdo->query("SELECT family_id FROM account_remember_tokens WHERE selector = '{$oldSelector}'")
                ->fetchColumn();

            $this->ageTokenPastRotationThrottle($oldSelector);

            self::assertSame(self::ACCOUNT_ID, $this->service->check());
            $this->applyInterceptedCookie();

            $oldRow = $this->pdo->query("SELECT used_at, family_id FROM account_remember_tokens WHERE selector = '{$oldSelector}'")
                ->fetch(PDO::FETCH_ASSOC);
            self::assertNotNull($oldRow['used_at']);

            $newSelector = explode(':', $_COOKIE[Config::$rememberMeCookieName], 2)[0];
            self::assertNotSame($oldSelector, $newSelector);

            $newFamily = $this->pdo->query("SELECT family_id FROM account_remember_tokens WHERE selector = '{$newSelector}'")
                ->fetchColumn();
            self::assertSame($oldFamily, $newFamily);
        }

        public function testReusingAnAlreadyRotatedTokenIsTreatedAsTheftAndInvalidatesTheAccount(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $this->applyInterceptedCookie();
            $staleCookie = $_COOKIE[Config::$rememberMeCookieName];
            $selector = explode(':', $staleCookie, 2)[0];

            $this->ageTokenPastRotationThrottle($selector);
            self::assertSame(self::ACCOUNT_ID, $this->service->check()); // rotates, consumes the old row

            // The attacker (or a stale browser tab) replays the pre-rotation cookie.
            $_COOKIE[Config::$rememberMeCookieName] = $staleCookie;

            self::assertNull($this->service->check());
            self::assertSame(
                0,
                (int)$this->pdo->query('SELECT COUNT(*) FROM account_remember_tokens WHERE account_id = ' . self::ACCOUNT_ID)->fetchColumn()
            );
        }

        public function testConsumeIsAtomicOnlyOneCallerWinsPerRow(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $row = $this->pdo->query('SELECT id FROM account_remember_tokens')->fetch(PDO::FETCH_ASSOC);

            $consume = (new ReflectionClass(RememberMeService::class))->getMethod('consume');
            $consume->setAccessible(true);

            self::assertTrue($consume->invoke($this->service, (int)$row['id']));
            self::assertFalse($consume->invoke($this->service, (int)$row['id']));
        }

        public function testWrongValidatorIsStillTreatedAsTheft(): void
        {
            $this->service->create(self::ACCOUNT_ID);
            $this->applyInterceptedCookie();
            $selector = explode(':', $_COOKIE[Config::$rememberMeCookieName], 2)[0];

            $_COOKIE[Config::$rememberMeCookieName] = $selector . ':' . bin2hex(random_bytes(32));

            self::assertNull($this->service->check());
            self::assertSame(
                0,
                (int)$this->pdo->query('SELECT COUNT(*) FROM account_remember_tokens WHERE account_id = ' . self::ACCOUNT_ID)->fetchColumn()
            );
        }

        /** Simulates the browser storing whatever the last intercepted setcookie() call set. */
        private function applyInterceptedCookie(): void
        {
            $value = $GLOBALS['__test_intercepted_cookies'][Config::$rememberMeCookieName] ?? null;
            self::assertIsString($value, 'Expected create()/rotation to have set the remember-me cookie');

            $_COOKIE[Config::$rememberMeCookieName] = $value;
        }

        private function ageTokenPastRotationThrottle(string $selector): void
        {
            $staleCreatedAt = date('Y-m-d H:i:s', time() - Config::$rememberMeRotationInterval - 1);
            $this->pdo->exec(
                "UPDATE account_remember_tokens SET date_created = '{$staleCreatedAt}' WHERE selector = '{$selector}'"
            );
        }
    }
}
