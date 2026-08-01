<?php

namespace NimblePHP\Authorization\Providers;

use InvalidArgumentException;
use JsonException;
use NimblePHP\Authorization\Interfaces\TokenProvider;
use krzysztofzylka\DatabaseManager\Table;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use NimblePHP\Authorization\Config;
use NimblePHP\Framework\Translation\Translation;

/**
 * JWT (JSON Web Token) provider for stateless token-based authentication
 *
 * Implements RFC 7519 JSON Web Token (JWT) standard
 * Supports token generation, validation, refresh, and revocation
 */
class JWTProvider implements TokenProvider
{
    /** @var list<string> */
    private const PROTECTED_CLAIMS = [
        'user_id',
        'sub',
        'iat',
        'nbf',
        'exp',
        'jti',
        'iss',
        'aud',
    ];

    private string $secret;
    private string $algorithm;
    private int $defaultExpirationTime;
    private int $maximumLifetime;
    private ?string $issuer;

    /** @var list<string>|null */
    private ?array $audience;

    private int $clockSkew;
    private Table $tokenBlacklist;

    /**
     * Construct JWT provider
     *
     * @param string $secret Secret key for signing tokens
     * @param string $algorithm Algorithm for signing (HS256, HS512, etc.)
     * @param int $defaultExpirationTime Default token expiration in seconds (default: 3600 = 1 hour)
     * @param string|null $issuer Expected issuer; null means tokens must not contain iss
     * @param string|list<string>|null $audience Expected audience; null means tokens must not contain aud
     * @param int $maximumLifetime Maximum allowed token lifetime in seconds
     * @param int $clockSkew Allowed clock skew in seconds
     */
    public function __construct(
        string $secret,
        string $algorithm = 'HS256',
        int $defaultExpirationTime = 3600,
        ?string $issuer = null,
        string|array|null $audience = null,
        int $maximumLifetime = 86400,
        int $clockSkew = 0
    ) {
        if (strlen($secret) < 32) {
            throw new InvalidArgumentException(Translation::getInstance()->translate('module.authorization.errors.jwt_secret_too_short'));
        }

        if ($defaultExpirationTime <= 0) {
            throw new InvalidArgumentException('JWT default expiration time must be greater than zero');
        }

        if ($maximumLifetime <= 0 || $defaultExpirationTime > $maximumLifetime) {
            throw new InvalidArgumentException('JWT maximum lifetime must be positive and cover the default expiration time');
        }

        if ($issuer !== null && trim($issuer) === '') {
            throw new InvalidArgumentException('JWT issuer cannot be empty');
        }

        if ($clockSkew < 0) {
            throw new InvalidArgumentException('JWT clock skew cannot be negative');
        }

        $this->secret = $secret;
        $this->algorithm = $algorithm;
        $this->defaultExpirationTime = $defaultExpirationTime;
        $this->maximumLifetime = $maximumLifetime;
        $this->issuer = $issuer === null ? null : trim($issuer);
        $this->audience = $this->normalizeConfiguredAudience($audience);
        $this->clockSkew = $clockSkew;
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
        if ($userId <= 0) {
            throw new InvalidArgumentException('JWT user ID must be a positive integer');
        }

        $this->assertCustomClaimsAreSafe($claims);
        $expiresIn = $expiresIn ?? $this->defaultExpirationTime;

        if ($expiresIn <= 0 || $expiresIn > $this->maximumLifetime) {
            throw new InvalidArgumentException(sprintf(
                'JWT lifetime must be between 1 and %d seconds',
                $this->maximumLifetime
            ));
        }

        $now = time();
        $expiration = $now + $expiresIn;

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT',
        ];

        $payload = $claims;
        $payload['user_id'] = $userId;
        $payload['sub'] = (string)$userId;
        $payload['iat'] = $now;
        $payload['nbf'] = $now;
        $payload['exp'] = $expiration;
        $payload['jti'] = bin2hex(random_bytes(16));

        if ($this->issuer !== null) {
            $payload['iss'] = $this->issuer;
        }

        if ($this->audience !== null) {
            $payload['aud'] = count($this->audience) === 1
                ? $this->audience[0]
                : $this->audience;
        }

        try {
            $headerEncoded = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
            $payloadEncoded = $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR));
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('JWT claims cannot be encoded as JSON', 0, $exception);
        }

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
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.jwt_invalid_format'));
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        $header = $this->decodeJsonSegment($headerEncoded, 'header');

        if (($header['alg'] ?? null) !== $this->algorithm || ($header['typ'] ?? null) !== 'JWT') {
            throw new \Exception('JWT header algorithm or type is invalid');
        }

        // Verify signature
        $expectedSignature = $this->base64UrlEncode(
            $this->sign($headerEncoded . '.' . $payloadEncoded)
        );

        if (!hash_equals($expectedSignature, $signatureEncoded)) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.jwt_invalid_signature'));
        }

        $payload = $this->decodeJsonSegment($payloadEncoded, 'payload');
        $this->validateRequiredClaims($payload);

        $now = time();

        if ($payload['iat'] > $now + $this->clockSkew) {
            throw new \Exception('JWT issued-at time is in the future');
        }

        if (array_key_exists('nbf', $payload)) {
            if (!is_int($payload['nbf']) || $payload['nbf'] < 0) {
                throw new \Exception('JWT nbf must be a non-negative integer');
            }

            if ($payload['nbf'] > $now + $this->clockSkew) {
                throw new \Exception('JWT is not valid yet');
            }

            if ($payload['nbf'] < $payload['iat'] || $payload['nbf'] >= $payload['exp']) {
                throw new \Exception('JWT not-before time is outside the token lifetime');
            }
        }

        if ($payload['exp'] <= $payload['iat']) {
            throw new \Exception('JWT expiration must be after issued-at time');
        }

        if ($payload['exp'] - $payload['iat'] > $this->maximumLifetime) {
            throw new \Exception('JWT lifetime exceeds the configured maximum');
        }

        if ($payload['exp'] <= $now - $this->clockSkew) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.jwt_expired'));
        }

        $this->validateIssuerAndAudience($payload);

        if ($this->isTokenRevoked($token)) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.jwt_revoked'));
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

            return $this->tokenBlacklist->insert([
                'token_jti' => $payload['jti'],
                'token_type' => 'jwt',
                'revoked_at' => date('Y-m-d H:i:s'),
            ]);
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

            if (!is_array($payload) || !isset($payload['jti']) || !is_string($payload['jti'])) {
                return true;
            }

            $statement = DatabaseManager::$connection->getConnection()->prepare(
                'SELECT 1 FROM account_token_blacklist WHERE token_jti = :jti LIMIT 1'
            );
            $statement->execute(['jti' => $payload['jti']]);

            return $statement->fetchColumn() !== false;
        } catch (\Throwable) {
            // Revocation storage failures must not turn into token acceptance.
            return true;
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

        foreach (self::PROTECTED_CLAIMS as $claim) {
            unset($payload[$claim]);
        }

        $expiresIn = $expiresIn ?? $this->defaultExpirationTime;
        $newToken = $this->generateToken($userId, $payload, $expiresIn);

        if (!$this->revokeToken($token)) {
            throw new \Exception('JWT refresh failed to revoke the previous token');
        }

        return $newToken;
    }

    /**
     * @param array<string|int, mixed> $claims
     */
    private function assertCustomClaimsAreSafe(array $claims): void
    {
        foreach (array_keys($claims) as $claim) {
            if (!is_string($claim) || trim($claim) === '') {
                throw new InvalidArgumentException('JWT custom claim names must be non-empty strings');
            }
        }

        $protected = array_values(array_intersect(self::PROTECTED_CLAIMS, array_keys($claims)));

        if ($protected !== []) {
            throw new InvalidArgumentException(sprintf(
                'Protected JWT claims cannot be supplied by the caller: %s',
                implode(', ', $protected)
            ));
        }
    }

    /**
     * @param string|list<string>|null $audience
     * @return list<string>|null
     */
    private function normalizeConfiguredAudience(string|array|null $audience): ?array
    {
        if ($audience === null) {
            return null;
        }

        $values = is_string($audience) ? [$audience] : array_values($audience);

        if ($values === []) {
            throw new InvalidArgumentException('JWT audience cannot be empty');
        }

        foreach ($values as $value) {
            if (!is_string($value) || trim($value) === '') {
                throw new InvalidArgumentException('JWT audience values must be non-empty strings');
            }
        }

        return array_values(array_unique(array_map('trim', $values)));
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonSegment(string $encoded, string $segment): array
    {
        try {
            $decoded = json_decode($this->base64UrlDecode($encoded), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new \Exception(sprintf('JWT %s is not valid JSON', $segment), 0, $exception);
        }

        if (!is_array($decoded)) {
            throw new \Exception(sprintf('JWT %s must be a JSON object', $segment));
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateRequiredClaims(array $payload): void
    {
        foreach (['user_id', 'iat', 'exp', 'jti'] as $claim) {
            if (!array_key_exists($claim, $payload)) {
                throw new \Exception(sprintf('JWT is missing required claim "%s"', $claim));
            }
        }

        if (!is_int($payload['user_id']) || $payload['user_id'] <= 0) {
            throw new \Exception('JWT user_id must be a positive integer');
        }

        foreach (['iat', 'exp'] as $claim) {
            if (!is_int($payload[$claim]) || $payload[$claim] < 0) {
                throw new \Exception(sprintf('JWT %s must be a non-negative integer', $claim));
            }
        }

        if (!is_string($payload['jti']) || preg_match('/^[a-f0-9]{32}$/D', $payload['jti']) !== 1) {
            throw new \Exception('JWT jti must be a 128-bit lowercase hexadecimal identifier');
        }

        if (
            array_key_exists('sub', $payload)
            && (!is_string($payload['sub']) || $payload['sub'] !== (string)$payload['user_id'])
        ) {
            throw new \Exception('JWT subject does not match user_id');
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateIssuerAndAudience(array $payload): void
    {
        if ($this->issuer === null) {
            if (array_key_exists('iss', $payload)) {
                throw new \Exception('JWT contains an issuer but none is configured');
            }
        } elseif (!isset($payload['iss']) || !is_string($payload['iss']) || $payload['iss'] !== $this->issuer) {
            throw new \Exception('JWT issuer is invalid');
        }

        if ($this->audience === null) {
            if (array_key_exists('aud', $payload)) {
                throw new \Exception('JWT contains an audience but none is configured');
            }

            return;
        }

        $tokenAudience = $payload['aud'] ?? null;
        $tokenAudience = is_string($tokenAudience) ? [$tokenAudience] : $tokenAudience;

        if (!is_array($tokenAudience) || $tokenAudience === []) {
            throw new \Exception('JWT audience is missing or invalid');
        }

        foreach ($tokenAudience as $value) {
            if (!is_string($value) || $value === '') {
                throw new \Exception('JWT audience is invalid');
            }
        }

        if (array_diff($this->audience, $tokenAudience) !== []) {
            throw new \Exception('JWT audience does not contain the configured recipient');
        }
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
        if ($data === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $data) !== 1) {
            throw new \Exception('JWT contains invalid base64url data');
        }

        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new \Exception('JWT contains invalid base64url data');
        }

        return $decoded;
    }
}
