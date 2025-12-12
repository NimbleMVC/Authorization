<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\TokenProvider;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;

/**
 * JWT (JSON Web Token) provider for stateless token-based authentication
 *
 * Implements RFC 7519 JSON Web Token (JWT) standard
 * Supports token generation, validation, refresh, and revocation
 */
class JWTProvider implements TokenProvider
{
    private string $secret;
    private string $algorithm;
    private int $defaultExpirationTime;
    private Table $tokenBlacklist;

    /**
     * Construct JWT provider
     *
     * @param string $secret Secret key for signing tokens
     * @param string $algorithm Algorithm for signing (HS256, HS512, etc.)
     * @param int $defaultExpirationTime Default token expiration in seconds (default: 3600 = 1 hour)
     */
    public function __construct(
        string $secret,
        string $algorithm = 'HS256',
        int $defaultExpirationTime = 3600
    ) {
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('Secret key must be at least 32 characters long for security');
        }

        $this->secret = $secret;
        $this->algorithm = $algorithm;
        $this->defaultExpirationTime = $defaultExpirationTime;
        $this->tokenBlacklist = new Table('account_token_blacklist');
    }

    /**
     * Generate JWT token
     *
     * @param int $userId User ID
     * @param array $claims Additional claims
     * @param int|null $expiresIn Expiration time in seconds
     * @return string Encoded JWT token
     */
    public function generateToken(int $userId, array $claims = [], ?int $expiresIn = null): string
    {
        $expiresIn = $expiresIn ?? $this->defaultExpirationTime;
        $now = time();
        $expiration = $now + $expiresIn;

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT',
        ];

        $payload = array_merge([
            'user_id' => $userId,
            'iat' => $now,
            'exp' => $expiration,
            'jti' => bin2hex(random_bytes(16)), // JWT ID for revocation
        ], $claims);

        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));

        $signature = $this->sign($headerEncoded . '.' . $payloadEncoded);
        $signatureEncoded = $this->base64UrlEncode($signature);

        return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
    }

    /**
     * Validate JWT token
     *
     * @param string $token JWT token
     * @return array Token payload
     * @throws \Exception If validation fails
     */
    public function validateToken(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \Exception('Invalid JWT token format');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        // Verify signature
        $expectedSignature = $this->base64UrlEncode(
            $this->sign($headerEncoded . '.' . $payloadEncoded)
        );

        if (!hash_equals($signatureEncoded, $expectedSignature)) {
            throw new \Exception('Invalid JWT signature');
        }

        // Decode payload
        $payload = json_decode($this->base64UrlDecode($payloadEncoded), true);

        if (!is_array($payload)) {
            throw new \Exception('Invalid JWT payload');
        }

        // Check expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new \Exception('JWT token has expired');
        }

        // Check if revoked
        if (isset($payload['jti']) && $this->isTokenRevoked($token)) {
            throw new \Exception('JWT token has been revoked');
        }

        if (!isset($payload['user_id'])) {
            throw new \Exception('JWT token missing user_id claim');
        }

        return $payload;
    }

    /**
     * Get token type
     *
     * @return string
     */
    public function getTokenType(): string
    {
        return 'jwt';
    }

    /**
     * Revoke JWT token
     *
     * @param string $token Token to revoke
     * @return bool
     */
    public function revokeToken(string $token): bool
    {
        try {
            $payload = $this->validateToken($token);

            if (!isset($payload['jti'])) {
                return false;
            }

            $this->tokenBlacklist->insert([
                'token_jti' => $payload['jti'],
                'token_type' => 'jwt',
                'revoked_at' => date('Y-m-d H:i:s'),
            ]);

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if token is revoked
     *
     * @param string $token Token to check
     * @return bool
     */
    public function isTokenRevoked(string $token): bool
    {
        try {
            $payload = json_decode($this->base64UrlDecode(explode('.', $token)[1]), true);

            if (!isset($payload['jti'])) {
                return false;
            }

            $blacklistedToken = $this->tokenBlacklist->findByField('token_jti', $payload['jti']);
            return $blacklistedToken !== null;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Refresh JWT token
     *
     * Validates current token and generates new one with extended expiration
     *
     * @param string $token Current token
     * @param int|null $expiresIn New expiration time
     * @return string New JWT token
     * @throws \Exception If current token is invalid
     */
    public function refreshToken(string $token, ?int $expiresIn = null): string
    {
        $payload = $this->validateToken($token);
        $userId = $payload['user_id'];

        // Remove used claims for refresh
        unset($payload['iat'], $payload['exp'], $payload['jti']);

        $expiresIn = $expiresIn ?? $this->defaultExpirationTime;
        return $this->generateToken($userId, $payload, $expiresIn);
    }

    /**
     * Sign data with secret key
     *
     * @param string $data Data to sign
     * @return string Signature
     */
    private function sign(string $data): string
    {
        return hash_hmac('sha256', $data, $this->secret, true);
    }

    /**
     * Base64 URL encode
     *
     * @param string $data Data to encode
     * @return string Encoded data
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decode
     *
     * @param string $data Data to decode
     * @return string Decoded data
     */
    private function base64UrlDecode(string $data): string
    {
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
