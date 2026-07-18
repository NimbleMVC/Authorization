<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Integration;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\DatabaseConnect;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use krzysztofzylka\DatabaseManager\Enum\DatabaseType;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\OAuthAccountLinkRequiredException;
use NimblePHP\Authorization\OAuth\OAuthIdentity;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use TypeError;

#[CoversClass(Authorization::class)]
final class AuthorizationOAuthIdentityTest extends TestCase
{
    private PDO $pdo;
    private Authorization $authorization;

    protected function setUp(): void
    {
        $_SESSION = [];
        Kernel::$projectPath = dirname(__DIR__, 2);
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        DatabaseManager::$connection = DatabaseConnect::create()
            ->setType(DatabaseType::sqlite)
            ->setConnection($this->pdo);

        Config::$tableName = 'oauth_accounts';
        Config::$columns = [
            'id' => 'user_id', 'username' => 'login_name',
            'email' => 'mail_address', 'password' => 'secret_hash',
            'active' => 'is_active', 'created_at' => 'created_on',
        ];
        Config::$oauthColumns = ['id' => 'external_subject', 'provider' => 'provider_name'];
        Config::$sessionKey = 'account_id';
        Config::$regenerateSessionOnLogin = false;

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE oauth_accounts (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_name TEXT NOT NULL,
                mail_address TEXT NOT NULL UNIQUE,
                secret_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL,
                created_on TEXT NOT NULL,
                external_subject TEXT NULL,
                provider_name TEXT NULL,
                UNIQUE (provider_name, external_subject)
            )
            SQL);

        $reflection = new ReflectionClass(Authorization::class);
        $this->authorization = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('session')->setValue($this->authorization, new Session());
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        Config::$tableName = 'accounts';
        Config::$columns = [
            'id' => 'id', 'username' => 'username', 'email' => 'email',
            'password' => 'password', 'active' => 'active', 'created_at' => 'date_created',
        ];
        Config::$oauthColumns = ['id' => 'account_oauth_id', 'provider' => 'account_oauth_provider'];
        Config::$sessionKey = 'account_id';
        Config::$regenerateSessionOnLogin = true;
    }

    public function testIdentityIsMatchedByProviderAndSubjectTogether(): void
    {
        $this->insertAccount('victim', 'victim@example.test', 'shared-subject', 'github');

        self::assertTrue($this->authorization->loginWithOAuth(new OAuthIdentity(
            provider: 'gitlab', subject: 'shared-subject', username: 'gitlab-user',
            email: 'gitlab@example.test', emailVerified: true,
        )));

        self::assertSame(2, $this->countAccounts());
        self::assertSame(2, $_SESSION['account_id']);
        self::assertSame('github', $this->accountById(1)['provider_name']);
        self::assertSame('shared-subject', $this->accountById(1)['external_subject']);
    }

    public function testVerifiedEmailCollisionRequiresExplicitLinkingAndDoesNotModifyAccount(): void
    {
        $this->insertAccount('victim', 'victim@example.test');

        try {
            $this->authorization->loginWithOAuth(new OAuthIdentity(
                provider: 'github', subject: 'attacker-subject', username: 'attacker',
                email: 'victim@example.test', emailVerified: true,
            ));
            self::fail('An e-mail collision must never link an OAuth identity automatically');
        } catch (OAuthAccountLinkRequiredException) {
            self::assertNull($this->accountById(1)['provider_name']);
            self::assertNull($this->accountById(1)['external_subject']);
            self::assertArrayNotHasKey('account_id', $_SESSION);
        }
    }

    public function testUnverifiedEmailCannotCreateAnAccount(): void
    {
        $this->expectException(InvalidArgumentException::class);

        try {
            $this->authorization->loginWithOAuth(new OAuthIdentity(
                provider: 'github', subject: 'subject-1', username: 'octocat',
                email: 'unverified@example.test', emailVerified: false,
            ));
        } finally {
            self::assertSame(0, $this->countAccounts());
        }
    }

    public function testAccountCreationUsesConfiguredColumnMappings(): void
    {
        self::assertTrue($this->authorization->loginWithOAuth(new OAuthIdentity(
            provider: 'github', subject: 'subject-2', username: 'octocat',
            email: 'verified@example.test', emailVerified: true,
        )));

        $account = $this->accountById(1);
        self::assertSame('octocat', $account['login_name']);
        self::assertSame('verified@example.test', $account['mail_address']);
        self::assertSame('github', $account['provider_name']);
        self::assertSame('subject-2', $account['external_subject']);
        self::assertSame(1, $account['is_active']);
        self::assertNotSame('', $account['secret_hash']);
        self::assertNotSame('', $account['created_on']);
    }

    public function testLoginRejectsCallerControlledArray(): void
    {
        $this->expectException(TypeError::class);
        /** @phpstan-ignore-next-line Intentionally verifies the public boundary. */
        $this->authorization->loginWithOAuth([
            'provider' => 'github', 'oauth_id' => 'subject',
            'email' => 'victim@example.test', 'username' => 'attacker',
        ]);
    }

    public function testAuthenticatedUserCanExplicitlyLinkIdentityAfterPasswordReauthentication(): void
    {
        $this->insertAccount('victim', 'victim@example.test');
        $_SESSION['account_id'] = 1;

        self::assertTrue($this->authorization->linkOAuthIdentity(
            new OAuthIdentity(
                provider: 'github', subject: 'verified-subject', username: 'victim',
                email: 'victim@example.test', emailVerified: true,
            ),
            'test-password',
        ));

        self::assertSame('github', $this->accountById(1)['provider_name']);
        self::assertSame('verified-subject', $this->accountById(1)['external_subject']);
    }

    public function testExplicitLinkRejectsInvalidPasswordWithoutModifyingAccount(): void
    {
        $this->insertAccount('victim', 'victim@example.test');
        $_SESSION['account_id'] = 1;

        $this->expectException(InvalidArgumentException::class);

        try {
            $this->authorization->linkOAuthIdentity(
                new OAuthIdentity(
                    provider: 'github', subject: 'attacker-subject', username: 'victim',
                    email: 'victim@example.test', emailVerified: true,
                ),
                'wrong-password',
            );
        } finally {
            self::assertNull($this->accountById(1)['provider_name']);
            self::assertNull($this->accountById(1)['external_subject']);
        }
    }

    private function insertAccount(string $username, string $email, ?string $subject = null, ?string $provider = null): void
    {
        $statement = $this->pdo->prepare(<<<'SQL'
            INSERT INTO oauth_accounts
                (login_name, mail_address, secret_hash, is_active, created_on, external_subject, provider_name)
            VALUES (:username, :email, :password, 1, :created, :subject, :provider)
            SQL);
        $statement->execute([
            'username' => $username, 'email' => $email,
            'password' => password_hash('test-password', PASSWORD_DEFAULT),
            'created' => date('Y-m-d H:i:s'), 'subject' => $subject, 'provider' => $provider,
        ]);
    }

    private function countAccounts(): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM oauth_accounts')->fetchColumn();
    }

    /** @return array<string, mixed> */
    private function accountById(int $id): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM oauth_accounts WHERE user_id = :id');
        $statement->execute(['id' => $id]);
        return $statement->fetch(PDO::FETCH_ASSOC);
    }
}
