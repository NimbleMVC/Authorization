<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Account;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\TokenProvider;
use NimblePHP\Authorization\OAuth\OAuthIdentity;
use NimblePHP\Authorization\Providers\JWTProvider;
use NimblePHP\Authorization\Exceptions\ValidationException;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Cookie;
use NimblePHP\Framework\Request;
use NimblePHP\Framework\Session;
use NimblePHP\Framework\Container\ServiceContainer;
use NimblePHP\Framework\Middleware\MiddlewareManager;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

#[CoversClass(Authorization::class)]
#[CoversClass(Account::class)]
final class AuthorizationAccountStateTest extends TestCase
{
    private const EPOCH_SESSION_KEY = 'account_auth_epoch';

    private PDO $pdo;
    private Authorization $authorization;

    protected function setUp(): void
    {
        $_SESSION = [];
        $_COOKIE = [];
        Kernel::$projectPath = dirname(__DIR__, 2);
        Kernel::$middlewareManager = new MiddlewareManager();
        Kernel::$serviceContainer = ServiceContainer::getInstance();
        Kernel::$serviceContainer->set('kernel.cookie', new Cookie(), false);
        Kernel::$serviceContainer->set('kernel.request', new Request(), false);

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);

        Config::$tableName = 'user';
        Config::$columns = [
            'id' => 'id', 'username' => 'username', 'email' => 'email',
            'password' => 'password', 'active' => 'active',
            'auth_epoch' => 'auth_epoch', 'created_at' => 'date_created',
        ];
        Config::$oauthColumns = ['id' => 'oauth_subject', 'provider' => 'oauth_provider'];
        Config::$sessionKey = 'account_id';
        Config::$requireActivation = false;
        Config::$regenerateSessionOnLogin = false;
        Config::$rateLimitEnabled = false;
        Config::$rememberMeEnabled = true;
        Config::$rememberMeTableName = 'account_remember_tokens';

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                auth_epoch INTEGER NOT NULL DEFAULT 0,
                date_created TEXT NOT NULL,
                oauth_subject TEXT NULL,
                oauth_provider TEXT NULL
            )
            SQL);
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_remember_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                selector TEXT NOT NULL,
                validator_hash TEXT NOT NULL,
                date_expired TEXT NOT NULL,
                date_created TEXT NOT NULL,
                date_modify TEXT NULL
            )
            SQL);
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
                last_used_at TEXT NULL,
                revoked_at TEXT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                date_created TEXT NULL,
                date_modify TEXT NULL
            )
            SQL);
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE account_api_key_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                key_hash TEXT,
                accessed_at TEXT,
                ip_address TEXT,
                user_agent TEXT,
                is_active INTEGER DEFAULT 1,
                date_created TEXT,
                date_modify TEXT
            )
            SQL);
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

        $this->authorization = $this->authorizationWithoutConstructor();
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
        Config::$oauthColumns = ['id' => 'account_oauth_id', 'provider' => 'account_oauth_provider'];
        Config::$sessionKey = 'account_id';
        Config::$requireActivation = false;
        Config::$regenerateSessionOnLogin = true;
        Config::$rateLimitEnabled = true;
        Config::$rememberMeEnabled = false;
        Config::$rememberMeTableName = 'account_remember_tokens';
    }

    public function testExistingSessionIsRejectedAndClearedAfterAccountDeactivation(): void
    {
        $this->insertAccount(active: 0, epoch: 1);
        $_SESSION['account_id'] = 1;
        $_SESSION[self::EPOCH_SESSION_KEY] = 0;

        self::assertFalse($this->authorization->isAuthorized());
        self::assertArrayNotHasKey('account_id', $_SESSION);
        self::assertArrayNotHasKey(self::EPOCH_SESSION_KEY, $_SESSION);
    }

    public function testExistingSessionIsRejectedWhenAccountWasDeleted(): void
    {
        $_SESSION['account_id'] = 999;
        $_SESSION[self::EPOCH_SESSION_KEY] = 0;

        self::assertFalse($this->authorization->isAuthorized());
        self::assertArrayNotHasKey('account_id', $_SESSION);
    }

    public function testExistingSessionIsRejectedWhenCredentialEpochChanged(): void
    {
        $this->insertAccount(active: 1, epoch: 4);
        $_SESSION['account_id'] = 1;
        $_SESSION[self::EPOCH_SESSION_KEY] = 3;

        self::assertFalse($this->authorization->isAuthorized());
        self::assertArrayNotHasKey('account_id', $_SESSION);
    }

    public function testAuthenticateAsRejectsInactiveAccountEvenWhenActivationIsNotRequired(): void
    {
        $this->insertAccount(active: 0);

        self::assertFalse($this->authorization->authenticateAs(1));
        self::assertArrayNotHasKey('account_id', $_SESSION);
    }

    public function testPasswordLoginRejectsInactiveAccountEvenWhenActivationIsNotRequired(): void
    {
        $this->insertAccount(active: 0);
        $this->expectException(ValidationException::class);

        try {
            $this->authorization->login('user', 'test-password');
        } finally {
            self::assertArrayNotHasKey('account_id', $_SESSION);
        }
    }

    public function testPendingChallengeCannotCompleteAfterAccountWasDeactivated(): void
    {
        $this->insertAccount(active: 0, epoch: 1);
        $_SESSION[Config::$challengeSessionKey] = 1;
        $_SESSION[Config::$challengeNameSessionKey] = 'external-check';
        $this->expectException(InvalidArgumentException::class);

        try {
            $this->authorization->completeChallenge();
        } finally {
            self::assertArrayNotHasKey(Config::$challengeSessionKey, $_SESSION);
            self::assertArrayNotHasKey(Config::$challengeNameSessionKey, $_SESSION);
            self::assertArrayNotHasKey('account_id', $_SESSION);
        }
    }

    public function testOAuthRejectsInactiveExistingAccount(): void
    {
        $this->insertAccount(active: 0, oauthSubject: 'subject-1', oauthProvider: 'github');

        $this->expectException(InvalidArgumentException::class);

        try {
            $this->authorization->loginWithOAuth(new OAuthIdentity(
                provider: 'github', subject: 'subject-1', username: 'user',
                email: 'user@example.test', emailVerified: true,
            ));
        } finally {
            self::assertArrayNotHasKey('account_id', $_SESSION);
        }
    }

    public function testTokenAuthenticationRequiresExistingActiveAccountAndMatchingEpoch(): void
    {
        $this->insertAccount(active: 1, epoch: 7);
        $provider = new AccountStateTokenProvider();
        Config::registerTokenProvider('account_state_test', $provider);

        $provider->validationResult = ['user_id' => 1, 'auth_epoch' => 7];
        self::assertTrue($this->authorization->authenticateWithToken('valid', 'account_state_test'));
        self::assertSame(1, $_SESSION['account_id']);
        self::assertSame(7, $_SESSION[self::EPOCH_SESSION_KEY]);

        $_SESSION = [];
        $provider->validationResult = ['user_id' => 1, 'auth_epoch' => 6];
        self::assertFalse($this->authorization->authenticateWithToken('old', 'account_state_test'));

        $provider->validationResult = ['user_id' => 1, 'auth_epoch' => -1];
        self::assertFalse($this->authorization->authenticateWithToken('negative-epoch', 'account_state_test'));

        $this->pdo->exec('UPDATE user SET active = 0 WHERE id = 1');
        $provider->validationResult = ['user_id' => 1, 'auth_epoch' => 7];
        self::assertFalse($this->authorization->authenticateWithToken('inactive', 'account_state_test'));

        $provider->validationResult = ['user_id' => 999, 'auth_epoch' => 0];
        self::assertFalse($this->authorization->authenticateWithToken('deleted', 'account_state_test'));
        self::assertArrayNotHasKey('account_id', $_SESSION);
    }

    public function testGeneratedTokenReceivesCurrentCredentialEpoch(): void
    {
        $this->insertAccount(active: 1, epoch: 9);
        $provider = new AccountStateTokenProvider();
        Config::registerTokenProvider('epoch_generation_test', $provider);

        self::assertSame('generated-token', $this->authorization->generateToken(
            1,
            'epoch_generation_test',
            ['purpose' => 'test', 'auth_epoch' => -1],
        ));
        self::assertSame(9, $provider->generatedClaims['auth_epoch']);
        self::assertSame('test', $provider->generatedClaims['purpose']);
    }

    public function testJwtIssuedBeforeEpochChangeCannotAuthenticateAgain(): void
    {
        $this->insertAccount(active: 1, epoch: 3);
        Config::registerTokenProvider('jwt_state_test', new JWTProvider(str_repeat('s', 32)));

        $token = $this->authorization->generateToken(1, 'jwt_state_test');
        self::assertTrue($this->authorization->authenticateWithToken($token, 'jwt_state_test'));

        $_SESSION = [];
        $this->pdo->exec('UPDATE user SET auth_epoch = auth_epoch + 1 WHERE id = 1');

        self::assertFalse($this->authorization->authenticateWithToken($token, 'jwt_state_test'));
        self::assertArrayNotHasKey('account_id', $_SESSION);
    }

    public function testDeactivationIncrementsEpochAndRevokesRememberMeAndApiKeys(): void
    {
        $this->insertAccount(active: 1, epoch: 2);
        $this->insertRememberToken(1);
        $this->insertApiKey(1, epoch: 2);
        $_SESSION['account_id'] = 1;
        $_SESSION[self::EPOCH_SESSION_KEY] = 2;

        self::assertTrue($this->account(1)->deactivate());

        $row = $this->accountRow(1);
        self::assertSame(0, $row['active']);
        self::assertSame(3, $row['auth_epoch']);
        self::assertSame(0, $this->tableCount('account_remember_tokens'));
        self::assertSame(0, $this->activeApiKeyCount(1));
        self::assertFalse($this->authorization->isAuthorized());
    }

    public function testPasswordChangeIncrementsEpochAndRevokesExistingCredentials(): void
    {
        $this->insertAccount(active: 1, epoch: 5);
        $this->insertRememberToken(1);
        $this->insertApiKey(1, epoch: 5);
        $_SESSION['account_id'] = 1;
        $_SESSION[self::EPOCH_SESSION_KEY] = 5;

        self::assertTrue($this->account(1)->changePassword('new-secure-password'));

        self::assertSame(6, $this->accountRow(1)['auth_epoch']);
        self::assertSame(0, $this->tableCount('account_remember_tokens'));
        self::assertSame(0, $this->activeApiKeyCount(1));
        self::assertFalse($this->authorization->isAuthorized());
    }

    private function authorizationWithoutConstructor(): Authorization
    {
        $reflection = new ReflectionClass(Authorization::class);
        $authorization = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('session')->setValue($authorization, new Session());
        $reflection->getProperty('account')->setValue($authorization, $this->account());
        return $authorization;
    }

    private function account(?int $id = null): Account
    {
        $reflection = new ReflectionClass(Account::class);
        $account = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('account')->setValue($account, new Table('user'));
        $reflection->getProperty('id')->setValue($account, $id);
        if ($id !== null) {
            $account->setId($id);
        }
        return $account;
    }

    private function insertAccount(
        int $active = 1,
        int $epoch = 0,
        ?string $oauthSubject = null,
        ?string $oauthProvider = null,
    ): void {
        $statement = $this->pdo->prepare(<<<'SQL'
            INSERT INTO user
                (username, email, password, active, auth_epoch, date_created, oauth_subject, oauth_provider)
            VALUES
                ('user', 'user@example.test', :password, :active, :epoch, :created, :subject, :provider)
            SQL);
        $statement->execute([
            'password' => Config::getPasswordHasher()->hash('test-password'),
            'active' => $active, 'epoch' => $epoch, 'created' => date('Y-m-d H:i:s'),
            'subject' => $oauthSubject, 'provider' => $oauthProvider,
        ]);
    }

    private function insertRememberToken(int $accountId): void
    {
        $statement = $this->pdo->prepare(<<<'SQL'
            INSERT INTO account_remember_tokens
                (account_id, selector, validator_hash, date_expired, date_created)
            VALUES (:account_id, 'selector', 'hash', :expires, :created)
            SQL);
        $statement->execute([
            'account_id' => $accountId,
            'expires' => date('Y-m-d H:i:s', time() + 3600),
            'created' => date('Y-m-d H:i:s'),
        ]);
    }

    private function insertApiKey(int $accountId, int $epoch): void
    {
        $statement = $this->pdo->prepare(<<<'SQL'
            INSERT INTO account_api_keys
                (user_id, key_hash, key_name, auth_epoch, is_active, created_at)
            VALUES (:account_id, :hash, 'test', :epoch, 1, :created)
            SQL);
        $statement->execute([
            'account_id' => $accountId, 'hash' => hash('sha256', 'key-' . $accountId),
            'epoch' => $epoch, 'created' => date('Y-m-d H:i:s'),
        ]);
    }

    /** @return array<string, mixed> */
    private function accountRow(int $id): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM user WHERE id = :id');
        $statement->execute(['id' => $id]);
        return $statement->fetch(PDO::FETCH_ASSOC);
    }

    private function tableCount(string $table): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn();
    }

    private function activeApiKeyCount(int $accountId): int
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM account_api_keys WHERE user_id = :id AND is_active = 1'
        );
        $statement->execute(['id' => $accountId]);
        return (int)$statement->fetchColumn();
    }
}

final class AccountStateTokenProvider implements TokenProvider
{
    /** @var array<string, mixed> */
    public array $validationResult = [];
    /** @var array<string, mixed> */
    public array $generatedClaims = [];

    public function generateToken(int $userId, array $claims = [], ?int $expiresIn = null): string
    {
        $this->generatedClaims = $claims;
        return 'generated-token';
    }

    public function validateToken(string $token): array
    {
        return $this->validationResult;
    }

    public function getTokenType(): string
    {
        return 'account_state_test';
    }

    public function revokeToken(string $token): bool
    {
        return true;
    }

    public function isTokenRevoked(string $token): bool
    {
        return false;
    }
}
