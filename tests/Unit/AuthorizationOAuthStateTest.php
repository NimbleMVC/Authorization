<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit;

use InvalidArgumentException;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\OAuthProvider;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

#[CoversClass(Authorization::class)]
final class AuthorizationOAuthStateTest extends TestCase
{
    private Authorization $authorization;

    protected function setUp(): void
    {
        $_SESSION = [];
        Kernel::$projectPath = dirname(__DIR__, 2);

        $reflection = new ReflectionClass(Authorization::class);
        $this->authorization = $reflection->newInstanceWithoutConstructor();
        $sessionProperty = $reflection->getProperty('session');
        $sessionProperty->setValue($this->authorization, new Session());
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    public function testInitiationStoresOnlyHashedStateWithProviderRedirectAndExpiry(): void
    {
        $provider = $this->registerProvider('github_state_storage');
        $redirectUri = 'https://example.test/oauth/callback';

        $authorizationUrl = $this->authorization->initiateOAuthLogin(
            'github_state_storage',
            $redirectUri
        );
        $state = $this->stateFromUrl($authorizationUrl);
        $flow = $_SESSION['oauth_flow'] ?? null;

        self::assertIsArray($flow);
        self::assertSame('github_state_storage', $flow['provider']);
        self::assertSame($redirectUri, $flow['redirect_uri']);
        self::assertSame(hash('sha256', $state), $flow['state_hash']);
        self::assertNotSame($state, $flow['state_hash']);
        self::assertGreaterThan(time(), $flow['expires_at']);
        self::assertSame($state, $provider->authorizationState);
    }

    public function testAuthorizationLayerGeneratesFreshStateForEveryFlow(): void
    {
        $this->registerProvider('github_fresh_state');

        $firstState = $this->stateFromUrl($this->authorization->initiateOAuthLogin(
            'github_fresh_state',
            'https://example.test/oauth/callback'
        ));
        $secondState = $this->stateFromUrl($this->authorization->initiateOAuthLogin(
            'github_fresh_state',
            'https://example.test/oauth/callback'
        ));

        self::assertNotSame($firstState, $secondState);
    }

    public function testCallbackRejectsMissingStateBeforeTokenExchange(): void
    {
        $provider = $this->registerProvider('github_missing_state');
        $this->authorization->initiateOAuthLogin(
            'github_missing_state',
            'https://example.test/oauth/callback'
        );

        try {
            $this->authorization->handleOAuthCallback('authorization-code', 'github_missing_state', '');
            self::fail('Callback without state must be rejected');
        } catch (InvalidArgumentException) {
            self::assertSame(0, $provider->exchangeCalls);
        }
    }

    public function testCallbackRejectsInvalidStateAndConsumesPendingFlow(): void
    {
        $provider = $this->registerProvider('github_invalid_state');
        $this->authorization->initiateOAuthLogin(
            'github_invalid_state',
            'https://example.test/oauth/callback'
        );

        try {
            $this->authorization->handleOAuthCallback(
                'authorization-code',
                'github_invalid_state',
                'attacker-controlled-state'
            );
            self::fail('Callback with invalid state must be rejected');
        } catch (InvalidArgumentException) {
            self::assertSame(0, $provider->exchangeCalls);
            self::assertArrayNotHasKey('oauth_flow', $_SESSION);
        }
    }

    public function testCallbackRejectsProviderMismatch(): void
    {
        $this->registerProvider('github_expected_provider');
        $unexpectedProvider = $this->registerProvider('github_unexpected_provider');
        $state = $this->stateFromUrl($this->authorization->initiateOAuthLogin(
            'github_expected_provider',
            'https://example.test/oauth/callback'
        ));

        try {
            $this->authorization->handleOAuthCallback(
                'authorization-code',
                'github_unexpected_provider',
                $state
            );
            self::fail('Callback for a different provider must be rejected');
        } catch (InvalidArgumentException) {
            self::assertSame(0, $unexpectedProvider->exchangeCalls);
            self::assertArrayNotHasKey('oauth_flow', $_SESSION);
        }
    }

    public function testCallbackRejectsExpiredState(): void
    {
        $provider = $this->registerProvider('github_expired_state');
        $state = 'expired-state';
        $_SESSION['oauth_flow'] = [
            'state_hash' => hash('sha256', $state),
            'provider' => 'github_expired_state',
            'redirect_uri' => 'https://example.test/oauth/callback',
            'expires_at' => time() - 1,
        ];
        // Legacy keys prove that the old callback ignores the protected flow.
        $_SESSION['oauth_provider'] = 'github_expired_state';
        $_SESSION['oauth_redirect_uri'] = 'https://example.test/oauth/callback';

        try {
            $this->authorization->handleOAuthCallback(
                'authorization-code',
                'github_expired_state',
                $state
            );
            self::fail('Expired OAuth state must be rejected');
        } catch (InvalidArgumentException) {
            self::assertSame(0, $provider->exchangeCalls);
        }
    }

    public function testValidStateIsSingleUseAndRedirectIsBoundToInitiation(): void
    {
        $provider = $this->registerProvider('github_valid_state');
        $redirectUri = 'https://example.test/oauth/callback';
        $state = $this->stateFromUrl($this->authorization->initiateOAuthLogin(
            'github_valid_state',
            $redirectUri
        ));

        $userData = $this->authorization->handleOAuthCallback(
            'authorization-code',
            'github_valid_state',
            $state
        );

        self::assertSame('oauth-subject', $userData['oauth_id']);
        self::assertSame($redirectUri, $provider->lastRedirectUri);
        self::assertArrayNotHasKey('oauth_flow', $_SESSION);
        self::assertSame(1, $provider->exchangeCalls);

        $this->expectException(InvalidArgumentException::class);

        try {
            $this->authorization->handleOAuthCallback(
                'replayed-authorization-code',
                'github_valid_state',
                $state
            );
        } finally {
            self::assertSame(1, $provider->exchangeCalls);
        }
    }

    private function registerProvider(string $name): RecordingOAuthProvider
    {
        $provider = new RecordingOAuthProvider($name);
        Config::registerOAuthProvider($name, $provider);

        return $provider;
    }

    private function stateFromUrl(string $url): string
    {
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

        self::assertArrayHasKey('state', $query);
        self::assertIsString($query['state']);
        self::assertNotSame('', $query['state']);

        return $query['state'];
    }
}

final class RecordingOAuthProvider implements OAuthProvider
{
    public ?string $authorizationState = null;

    public ?string $lastRedirectUri = null;

    public int $exchangeCalls = 0;

    public function __construct(private readonly string $name)
    {
    }

    public function getAuthorizationUrl(
        string $redirectUri,
        array $scopes = [],
        ?string $state = null
    ): string {
        $this->authorizationState = $state ?? 'provider-generated-static-state';

        return 'https://provider.test/authorize?' . http_build_query([
            'redirect_uri' => $redirectUri,
            'state' => $this->authorizationState,
        ]);
    }

    public function exchangeCodeForToken(string $code, string $redirectUri): string
    {
        $this->exchangeCalls++;
        $this->lastRedirectUri = $redirectUri;

        return 'access-token';
    }

    public function getUserData(string $accessToken): array
    {
        return [
            'oauth_id' => 'oauth-subject',
            'oauth_provider' => $this->name,
            'username' => 'oauth-user',
            'email' => 'oauth@example.test',
        ];
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getClientId(): string
    {
        return 'client-id';
    }

    public function getClientSecret(): string
    {
        return 'client-secret';
    }
}
