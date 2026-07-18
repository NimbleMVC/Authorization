<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\OAuth;

use NimblePHP\Authorization\OAuth\GitHubIdentityNormalizer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(GitHubIdentityNormalizer::class)]
final class GitHubIdentityNormalizerTest extends TestCase
{
    public function testUsesOnlyPrimaryVerifiedEmail(): void
    {
        $result = (new GitHubIdentityNormalizer())->normalize(
            ['id' => 123, 'login' => 'octocat', 'email' => null],
            [
                ['email' => 'unverified@example.test', 'primary' => true, 'verified' => false],
                ['email' => 'verified@example.test', 'primary' => true, 'verified' => true],
            ],
        );

        self::assertSame('verified@example.test', $result['email']);
        self::assertTrue($result['email_verified']);
    }

    public function testPublicProfileEmailIsNotTrustedWithoutVerifiedEmailRecord(): void
    {
        $result = (new GitHubIdentityNormalizer())->normalize(
            ['id' => 123, 'login' => 'octocat', 'email' => 'profile@example.test'],
            [],
        );

        self::assertSame('', $result['email']);
        self::assertFalse($result['email_verified']);
    }
}
