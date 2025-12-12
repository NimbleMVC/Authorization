<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\TwoFactorProvider;

/**
 * Time-based One-Time Password (TOTP) provider for 2FA
 *
 * Implements RFC 6238 standard for time-based one-time passwords.
 * Compatible with authenticator apps like Google Authenticator, Microsoft Authenticator,
 * Authy, and others.
 *
 * Generates QR codes that users can scan to add accounts to their authenticator app.
 */
class TOTPProvider implements TwoFactorProvider
{
    /**
     * Length of the OTP code
     *
     * @var int
     */
    private int $codeLength = 6;

    /**
     * Time step in seconds (typically 30)
     *
     * @var int
     */
    private int $timeStep = 30;

    /**
     * Hash algorithm to use
     *
     * @var string
     */
    private string $algorithm = 'sha1';

    /**
     * Number of windows to accept (before/after current time)
     *
     * @var int
     */
    private int $discrepancy = 1;

    /**
     * Service/company name for display in authenticator apps
     *
     * @var string
     */
    private string $issuer = 'NimblePHP Authorization';

    /**
     * Create a new TOTPProvider
     *
     * @param string $issuer Service name shown in authenticator apps
     * @param int $codeLength Length of generated codes (default: 6)
     * @param int $timeStep Time step in seconds (default: 30)
     */
    public function __construct(string $issuer = 'NimblePHP Authorization', int $codeLength = 6, int $timeStep = 30)
    {
        $this->issuer = $issuer;
        $this->codeLength = $codeLength;
        $this->timeStep = $timeStep;
    }

    /**
     * Generate a new TOTP secret
     *
     * @return string Base32 encoded secret
     */
    public function generateSecret(): string
    {
        $randomBytes = random_bytes(20);
        return $this->base32Encode($randomBytes);
    }

    /**
     * Generate a TOTP code from a secret
     *
     * @param string $secret Base32 encoded secret
     * @return string The 6-digit code
     */
    public function generateCode(string $secret): string
    {
        $secretDecoded = $this->base32Decode($secret);
        $time = floor(time() / $this->timeStep);

        return $this->generateOTP($secretDecoded, $time);
    }

    /**
     * Verify a code against a secret
     *
     * @param string $secret Base32 encoded secret
     * @param string $code The code to verify
     * @return bool True if code is valid
     */
    public function verify(string $secret, string $code): bool
    {
        return $this->isCodeValid($secret, $code);
    }

    /**
     * Check if a code is valid and not expired
     *
     * @param string $secret Base32 encoded secret
     * @param string $code The code to check
     * @return bool True if code is valid and current
     */
    public function isCodeValid(string $secret, string $code): bool
    {
        $secretDecoded = $this->base32Decode($secret);
        $time = floor(time() / $this->timeStep);

        for ($i = -$this->discrepancy; $i <= $this->discrepancy; $i++) {
            $calculatedCode = $this->generateOTP($secretDecoded, $time + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the provider name
     *
     * @return string Always returns 'totp'
     */
    public function getName(): string
    {
        return 'totp';
    }

    /**
     * Generate QR code URL for scanning in authenticator app
     *
     * Uses the otpauth:// URI scheme which is standard for authenticator apps.
     *
     * @param string $secret The TOTP secret
     * @param string $accountName User identifier (email or username)
     * @param string|null $issuer Custom issuer name (overrides default)
     * @return string The otpauth:// URI
     */
    public function getQRCodeURI(string $secret, string $accountName, ?string $issuer = null): string
    {
        $issuer = $issuer ?? $this->issuer;

        $label = rawurlencode($issuer . ':' . $accountName);
        $params = [
            'secret' => $secret,
            'issuer' => rawurlencode($issuer),
            'algorithm' => strtoupper($this->algorithm),
            'digits' => $this->codeLength,
            'period' => $this->timeStep,
        ];

        $query = http_build_query($params);
        return "otpauth://totp/{$label}?{$query}";
    }

    /**
     * Generate a QR code image URL using a QR code generation service
     *
     * Uses Google Charts API for generating QR codes. You can replace this
     * with your preferred QR code generator.
     *
     * @param string $secret The TOTP secret
     * @param string $accountName User identifier (email or username)
     * @param int $size QR code size in pixels (default: 300)
     * @param string|null $issuer Custom issuer name
     * @return string URL to QR code image
     */
    public function getQRCodeImageURL(string $secret, string $accountName, int $size = 300, ?string $issuer = null): string
    {
        $uri = $this->getQRCodeURI($secret, $accountName, $issuer);
        $encodedURI = rawurlencode($uri);

        return "https://chart.googleapis.com/chart?chs={$size}x{$size}&chld=M|0&cht=qr&chl={$encodedURI}";
    }

    /**
     * Generate recovery codes (backup codes for users)
     *
     * These codes can be used as a fallback if the user loses access to their authenticator app.
     *
     * @param string $secret The TOTP secret (not used for recovery codes)
     * @param int $count Number of codes to generate (default: 10)
     * @return array<int, string> Array of recovery codes
     */
    public function getRecoveryCodes(string $secret, int $count = 10): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 8);
            $codes[] = chunk_split($code, 4, '-');
        }
        return $codes;
    }

    /**
     * Verify a recovery code
     *
     * Recovery codes are stored separately and marked as used after verification.
     * This is a basic implementation - you may need to extend this in your application
     * to store and track used recovery codes in your database.
     *
     * @param string $secret Not used for recovery code verification
     * @param string $code The recovery code to verify
     * @return bool True if code is valid format
     */
    public function verifyRecoveryCode(string $secret, string $code): bool
    {
        return preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', strtoupper($code)) === 1;
    }

    /**
     * Generate an OTP for a given secret and time
     *
     * @param string $secret The decoded secret bytes
     * @param int $time The time counter
     * @return string The OTP code
     */
    private function generateOTP(string $secret, int $time): string
    {
        $timeBytes = '';
        for ($i = 7; $i >= 0; $i--) {
            $timeBytes = chr($time & 0xff) . $timeBytes;
            $time = $time >> 8;
        }

        $hash = hash_hmac($this->algorithm, $timeBytes, $secret, true);
        $offset = ord($hash[19]) & 0x0f;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % pow(10, $this->codeLength);

        return str_pad((string)$code, $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Encode bytes to Base32
     *
     * @param string $input Raw bytes
     * @return string Base32 encoded string
     */
    private function base32Encode(string $input): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;

        for ($i = 0; $i < strlen($input); $i++) {
            $v = ($v << 8) | ord($input[$i]);
            $vbits += 8;
            while ($vbits >= 5) {
                $vbits -= 5;
                $output .= $alphabet[($v >> $vbits) & 31];
            }
        }

        if ($vbits > 0) {
            $output .= $alphabet[($v << (5 - $vbits)) & 31];
        }

        return $output;
    }

    /**
     * Decode Base32 to bytes
     *
     * @param string $input Base32 encoded string
     * @return string Raw bytes
     */
    private function base32Decode(string $input): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;

        for ($i = 0; $i < strlen($input); $i++) {
            $char = strtoupper($input[$i]);
            $digit = strpos($alphabet, $char);
            if ($digit === false) {
                continue;
            }
            $v = ($v << 5) | $digit;
            $vbits += 5;
            if ($vbits >= 8) {
                $vbits -= 8;
                $output .= chr(($v >> $vbits) & 255);
            }
        }

        return $output;
    }
}
