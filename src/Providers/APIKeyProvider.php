<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\TokenProvider;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;

/**
 * API Keys provider for stateful token-based authentication
 *
 * Generates and validates API keys with:
 * - Rate limiting per key
 * - Named keys for identification
 * - Scopes for permission control
 * - Expiration and revocation support
 */
class APIKeyProvider implements TokenProvider
{
    private Table $keysTable;
    private Table $keyUsageTable;

    /**
     * Construct API Key provider
     */
    public function __construct()
    {
        $this->keysTable = new Table('account_api_keys');
        $this->keyUsageTable = new Table('account_api_key_usage');
    }

    /**
     * Generate API key
     *
     * @param int $userId User ID
     * @param array $claims Additional metadata (name, scopes, etc.)
     * @param int|null $expiresIn Expiration time in seconds
     * @return string Generated API key
     */
    public function generateToken(int $userId, array $claims = [], ?int $expiresIn = null): string
    {
        $key = 'sk_' . bin2hex(random_bytes(24)); // 48 characters
        $keyHash = hash('sha256', $key);

        $expiresAt = null;
        if ($expiresIn !== null) {
            $expiresAt = date('Y-m-d H:i:s', time() + $expiresIn);
        }

        $this->keysTable->insert([
            'user_id' => $userId,
            'key_hash' => $keyHash,
            'key_name' => $claims['name'] ?? 'API Key',
            'scopes' => isset($claims['scopes']) ? json_encode($claims['scopes']) : null,
            'rate_limit' => $claims['rate_limit'] ?? 1000, // requests per hour
            'expires_at' => $expiresAt,
            'created_at' => date('Y-m-d H:i:s'),
            'last_used_at' => null,
            'is_active' => 1,
        ]);

        return $key;
    }

    /**
     * Validate API key
     *
     * @param string $token API key
     * @return array Key data
     * @throws \Exception If validation fails
     */
    public function validateToken(string $token): array
    {
        if (!preg_match('/^sk_[a-f0-9]{48}$/', $token)) {
            throw new \Exception('Invalid API key format');
        }

        $keyHash = hash('sha256', $token);
        $keyData = $this->keysTable->findByField('key_hash', $keyHash);

        if (!$keyData) {
            throw new \Exception('API key not found or invalid');
        }

        $tableName = 'account_api_keys';
        $keyRecord = $keyData[$tableName];

        // Check if active
        if (!$keyRecord['is_active']) {
            throw new \Exception('API key is inactive');
        }

        // Check expiration
        if ($keyRecord['expires_at'] && strtotime($keyRecord['expires_at']) < time()) {
            throw new \Exception('API key has expired');
        }

        // Update last used timestamp
        $this->keysTable->updateByConditions(
            ['last_used_at' => date('Y-m-d H:i:s')],
            ['key_hash' => $keyHash]
        );

        // Log usage
        $this->keyUsageTable->insert([
            'key_hash' => $keyHash,
            'user_id' => $keyRecord['user_id'],
            'accessed_at' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        ]);

        return [
            'user_id' => $keyRecord['user_id'],
            'key_name' => $keyRecord['key_name'],
            'scopes' => $keyRecord['scopes'] ? json_decode($keyRecord['scopes'], true) : [],
            'rate_limit' => $keyRecord['rate_limit'],
        ];
    }

    /**
     * Get token type
     *
     * @return string
     */
    public function getTokenType(): string
    {
        return 'api_key';
    }

    /**
     * Revoke API key
     *
     * @param string $token API key to revoke
     * @return bool
     */
    public function revokeToken(string $token): bool
    {
        try {
            $keyHash = hash('sha256', $token);

            return $this->keysTable->updateByConditions(
                ['is_active' => 0],
                ['key_hash' => $keyHash]
            );
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if token is revoked (deactivated)
     *
     * @param string $token API key to check
     * @return bool
     */
    public function isTokenRevoked(string $token): bool
    {
        try {
            $keyHash = hash('sha256', $token);
            $keyData = $this->keysTable->findByField('key_hash', $keyHash);

            if (!$keyData) {
                return true; // Non-existent keys are "revoked"
            }

            $tableName = 'account_api_keys';
            return !$keyData[$tableName]['is_active'];
        } catch (\Exception $e) {
            return true;
        }
    }

    /**
     * List API keys for user
     *
     * @param int $userId User ID
     * @return array List of API keys (without hashes)
     */
    public function listUserKeys(int $userId): array
    {
        try {
            $result = $this->keysTable->findAll([
                'user_id' => $userId,
            ]);

            if (!$result) {
                return [];
            }

            $keys = [];
            foreach ($result['account_api_keys'] ?? [] as $key) {
                $keys[] = [
                    'id' => $key['id'],
                    'name' => $key['key_name'],
                    'created_at' => $key['created_at'],
                    'last_used_at' => $key['last_used_at'],
                    'expires_at' => $key['expires_at'],
                    'is_active' => $key['is_active'],
                ];
            }

            return $keys;
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Get API key by ID
     *
     * @param int $keyId Key ID
     * @param int $userId User ID (for verification)
     * @return array|null Key data
     */
    public function getKey(int $keyId, int $userId): ?array
    {
        try {
            $result = $this->keysTable->findByConditions([
                'id' => $keyId,
                'user_id' => $userId,
            ]);

            if (!$result) {
                return null;
            }

            $tableName = 'account_api_keys';
            $key = $result[$tableName];

            return [
                'id' => $key['id'],
                'name' => $key['key_name'],
                'created_at' => $key['created_at'],
                'last_used_at' => $key['last_used_at'],
                'expires_at' => $key['expires_at'],
                'is_active' => $key['is_active'],
            ];
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Update API key metadata
     *
     * @param int $keyId Key ID
     * @param int $userId User ID (for verification)
     * @param array $updates Updates (name, rate_limit, scopes, expires_at)
     * @return bool
     */
    public function updateKey(int $keyId, int $userId, array $updates): bool
    {
        try {
            $allowed = ['key_name' => 'name', 'rate_limit' => 'rate_limit', 'scopes' => 'scopes', 'expires_at' => 'expires_at'];
            $data = [];

            foreach ($allowed as $column => $updateKey) {
                if (isset($updates[$updateKey])) {
                    if ($updateKey === 'scopes') {
                        $data[$column] = json_encode($updates[$updateKey]);
                    } else if ($updateKey === 'name') {
                        $data['key_name'] = $updates[$updateKey];
                    } else {
                        $data[$column] = $updates[$updateKey];
                    }
                }
            }

            if (empty($data)) {
                return false;
            }

            return $this->keysTable->updateByConditions(
                $data,
                ['id' => $keyId, 'user_id' => $userId]
            );
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check API key rate limit
     *
     * @param string $token API key
     * @return array Rate limit info
     */
    public function getRateLimit(string $token): array
    {
        try {
            $data = $this->validateToken($token);
            $limit = $data['rate_limit'];
            $keyHash = hash('sha256', $token);

            // Count requests in last hour
            $oneHourAgo = date('Y-m-d H:i:s', time() - 3600);
            $result = $this->keyUsageTable->findAll([
                'key_hash' => $keyHash,
                'accessed_at >' => $oneHourAgo,
            ]);

            $count = count($result['account_api_key_usage'] ?? []);

            return [
                'limit' => $limit,
                'used' => $count,
                'remaining' => max(0, $limit - $count),
            ];
        } catch (\Exception $e) {
            return ['limit' => 0, 'used' => 0, 'remaining' => 0];
        }
    }
}
