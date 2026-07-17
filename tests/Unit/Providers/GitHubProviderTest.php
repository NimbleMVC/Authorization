<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Providers;

use InvalidArgumentException;
use NimblePHP\Authorization\Providers\GitHubProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(GitHubProvider::class)]
final class GitHubProviderTest extends TestCase
{
    public function testAuthorizationUrlUsesStateOwnedByAuthorizationLayer(): void
    {
        $provider = new GitHubProvider('client-id', 'client-secret');
        $redirectUri = 'https://example.test/oauth/callback';
        $state = bin2hex(random_bytes(32));

        $url = $provider->getAuthorizationUrl($redirectUri, ['read:user'], $state);
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

        self::assertSame('client-id', $query['client_id']);
        self::assertSame($redirectUri, $query['redirect_uri']);
        self::assertSame('read:user', $query['scope']);
        self::assertSame($state, $query['state']);
    }

    public function testAuthorizationUrlFailsClosedWithoutState(): void
    {
        $provider = new GitHubProvider('client-id', 'client-secret');

        $this->expectException(InvalidArgumentException::class);
        $provider->getAuthorizationUrl('https://example.test/oauth/callback');
    }
}
