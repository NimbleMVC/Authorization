<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Tests\Unit\Providers;

use NimblePHP\Authorization\Providers\TOTPProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TOTPProvider::class)]
final class TOTPProviderTest extends TestCase
{
    private TOTPProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new TOTPProvider();
    }

    public function testGeneratesBase32SecretUsingCryptographicRandomness(): void
    {
        $firstSecret = $this->provider->generateSecret();
        $secondSecret = $this->provider->generateSecret();

        self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $firstSecret);
        self::assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $secondSecret);
        self::assertNotSame($firstSecret, $secondSecret);
    }

    public function testGeneratedTotpCodeCanBeVerified(): void
    {
        $secret = $this->provider->generateSecret();
        $code = $this->provider->generateCode($secret);

        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
        self::assertTrue($this->provider->verify($secret, $code));
        self::assertTrue($this->provider->isCodeValid($secret, $code));
    }

    public function testInvalidTotpCodeIsRejected(): void
    {
        $secret = $this->provider->generateSecret();
        $validCode = $this->provider->generateCode($secret);
        $invalidCode = $validCode === '000000' ? '000001' : '000000';

        self::assertFalse($this->provider->verify($secret, $invalidCode));
    }

    public function testRecoveryCodesAreDistinctAndHaveCanonicalFormat(): void
    {
        $codes = $this->provider->getRecoveryCodes($this->provider->generateSecret());

        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $code);
        }
    }

    public function testArbitraryFormattedRecoveryCodeIsRejected(): void
    {
        self::assertFalse(
            $this->provider->verifyRecoveryCode(
                $this->provider->generateSecret(),
                'AAAA-AAAA'
            )
        );
    }

    /**
     * AUT-H07 regression guard: the provider must never expose a method that
     * ships the TOTP secret to a third-party QR rendering service again.
     */
    public function testProviderExposesNoRemoteQrCodeRenderingMethod(): void
    {
        self::assertFalse(method_exists($this->provider, 'getQRCodeImageURL'));
    }

    public function testQrCodeUriIsLocalOtpauthWithNoExternalHost(): void
    {
        $secret = $this->provider->generateSecret();
        $uri = $this->provider->getQRCodeURI($secret, 'alice@example.com');

        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertStringContainsString('secret=' . $secret, $uri);
        self::assertStringNotContainsString('http://', $uri);
        self::assertStringNotContainsString('https://', $uri);
    }
}
