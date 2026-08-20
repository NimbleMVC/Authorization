<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\TokenProvider;
use NimblePHP\Authorization\Interfaces\AccountTokenRevoker;
use krzysztofzylka\DatabaseManager\Table;
use krzysztofzylka\DatabaseManager\DatabaseManager;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\InsufficientScopeException;
use NimblePHP\Authorization\Exceptions\RateLimitExceededException;
use NimblePHP\Framework\Translation\Translation;

/**
 * API Keys provider for stateful token-based authentication
 *
 * Generates and validates API keys with:
 * - Usage logging and an atomically enforced per-key rate limit (window: 1 hour,
 *   bypass with Config::$apiKeyRateLimitEnforced = false)
 * - Named keys for identification
 * - Scope metadata; enforce it per endpoint with hasScope()/requireScope() -
 *   this module does not map routes to scopes
 * - Expiration and revocation support
 */
class APIKeyProvider implements TokenProvider, AccountTokenRevoker
{
    /** Rate limit window, in seconds (matches the "requests per hour" semantics of rate_limit). */
    private const RATE_LIMIT_WINDOW_SECONDS = 3600;

    /** How long usage log rows are kept for auditing before being pruned. */
    private const USAGE_LOG_RETENTION_SECONDS = 86400;

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
            'auth_epoch' => $claims['auth_epoch'] ?? 0,
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
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.apikey_invalid_format'));
        }

        $keyHash = hash('sha256', $token);
        $keyData = $this->keysTable->find(['key_hash' => $keyHash]);

        if (!$keyData) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.apikey_not_found'));
        }

        $tableName = 'account_api_keys';
        $keyRecord = $keyData[$tableName];

        // Check if active
        if (!$keyRecord['is_active']) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.apikey_inactive'));
        }

        // Check expiration
        if ($keyRecord['expires_at'] && strtotime($keyRecord['expires_at']) < time()) {
            throw new \Exception(Translation::getInstance()->translate('module.authorization.errors.apikey_expired'));
        }

        // Atomic: a key over its rate limit must not be accepted.
        if (
            Config::isApiKeyRateLimitEnforced()
            && !$this->consumeRateLimit((int)$keyRecord['id'], (int)$keyRecord['rate_limit'])
        ) {
            throw new RateLimitExceededException(
                Translation::getInstance()->translate('module.authorization.errors.apikey_rate_limited')
            );
        }

        $this->keysTable->setId($keyRecord['id'])->update(['last_used_at' => date('Y-m-d H:i:s')]);

        $this->keyUsageTable->insert([
            'key_hash' => $keyHash,
            'user_id' => $keyRecord['user_id'],
            'accessed_at' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        ]);

        $this->pruneUsageLog($keyHash);

        return [
            'user_id' => $keyRecord['user_id'],
            'key_name' => $keyRecord['key_name'],
            'scopes' => $keyRecord['scopes'] ? json_decode($keyRecord['scopes'], true) : [],
            'rate_limit' => $keyRecord['rate_limit'],
            'auth_epoch' => $keyRecord['auth_epoch'],
        ];
    }

    /**
     * Atomically consume one request against the key's rolling hourly limit.
     *
     * A single conditional UPDATE evaluates the window and the limit and applies
     * the increment together, so concurrent requests against the same key cannot
     * race past the limit the way a separate count-then-insert check would.
     *
     * @param int $keyId Key row ID
     * @param int $limit Requests allowed per window (a non-positive limit blocks every request)
     * @return bool True if the request was accepted and counted
     */
    private function consumeRateLimit(int $keyId, int $limit): bool
    {
        $now = date('Y-m-d H:i:s');
        $windowStart = date('Y-m-d H:i:s', time() - self::RATE_LIMIT_WINDOW_SECONDS);

        $statement = DatabaseManager::$connection->getConnection()->prepare(
            'UPDATE account_api_keys SET'
            . ' rate_window_count = CASE'
            . '   WHEN rate_window_started_at IS NULL OR rate_window_started_at <= :window_start_reset'
            . '   THEN 1 ELSE rate_window_count + 1 END,'
            . ' rate_window_started_at = CASE'
            . '   WHEN rate_window_started_at IS NULL OR rate_window_started_at <= :window_start_set'
            . '   THEN :now ELSE rate_window_started_at END'
            . ' WHERE id = :id'
            . ' AND ('
            . '   rate_window_started_at IS NULL'
            . '   OR rate_window_started_at <= :window_start_guard'
            . '   OR rate_window_count < :limit'
            . ' )'
        );

        $statement->execute([
            'window_start_reset' => $windowStart,
            'window_start_set' => $windowStart,
            'window_start_guard' => $windowStart,
            'now' => $now,
            'id' => $keyId,
            'limit' => $limit,
        ]);

        return $statement->rowCount() === 1;
    }

    /** Drop usage-log rows older than the retention window so the table does not grow unbounded. */
    private function pruneUsageLog(string $keyHash): void
    {
        $cutoff = date('Y-m-d H:i:s', time() - self::USAGE_LOG_RETENTION_SECONDS);

        $statement = DatabaseManager::$connection->getConnection()->prepare(
            'DELETE FROM account_api_key_usage WHERE key_hash = :key_hash AND accessed_at < :cutoff'
        );
        $statement->execute(['key_hash' => $keyHash, 'cutoff' => $cutoff]);
    }

    /**
     * Check whether validated token data carries a scope.
     *
     * @param array $tokenData Result of validateToken()/Authorization::validateToken()
     * @param string $scope Scope to check for, e.g. "write:posts"
     * @return bool
     */
    public function hasScope(array $tokenData, string $scope): bool
    {
        return in_array($scope, $tokenData['scopes'] ?? [], true);
    }

    /**
     * Require that validated token data carries one or more scopes.
     *
     * Call this after Authorization::validateToken() once the endpoint knows which
     * scope(s) it needs - the module has no route-to-scope mapping of its own.
     *
     * @param array $tokenData Result of validateToken()/Authorization::validateToken()
     * @param string|string[] $scopes Scope(s) that must all be present
     * @throws InsufficientScopeException If any required scope is missing
     */
    public function requireScope(array $tokenData, string|array $scopes): void
    {
        $required = is_array($scopes) ? $scopes : [$scopes];
        $missing = array_values(array_filter($required, fn(string $scope): bool => !$this->hasScope($tokenData, $scope)));

        if (!empty($missing)) {
            throw new InsufficientScopeException(
                Translation::getInstance()->translate('module.authorization.errors.apikey_scope_missing')
                . ': ' . implode(', ', $missing)
            );
        }
    }

    /** Revoke every API key issued to an account. */
    public function revokeAllForAccount(int $accountId): bool
    {
        $statement = DatabaseManager::$connection->getConnection()->prepare(
            'UPDATE account_api_keys'
            . ' SET is_active = 0, revoked_at = :revoked_at'
            . ' WHERE user_id = :account_id AND is_active = 1'
        );

        return $statement->execute([
            'revoked_at' => date('Y-m-d H:i:s'),
            'account_id' => $accountId,
        ]);
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
            $keyData = $this->keysTable->find(['key_hash' => $keyHash]);

            if (!$keyData) {
                return false;
            }

            $tableName = 'account_api_keys';
            return $this->keysTable->setId($keyData[$tableName]['id'])->update(['is_active' => 0]);
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

            $keyData = $this->keysTable->find(['key_hash' => $keyHash]);

            if (!$keyData) {
                return true;
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

            foreach ($result as $row) {
                $key = $row['account_api_keys'] ?? $row;
                $keys[] = [
                    'id' => $key['id'],
                    'user_id' => $key['user_id'],
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
            $result = $this->keysTable->find([
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
     * Revoke API key by ID
     *
     * @param int $keyId Key ID
     * @param int $userId User ID (for verification)
     * @return bool
     */
    public function revokeById(int $keyId, int $userId): bool
    {
        try {
            $existing = $this->keysTable->find(['id' => $keyId, 'user_id' => $userId]);

            if (!$existing) {
                return false;
            }

            return $this->keysTable->setId($keyId)->update(['is_active' => 0]);
        } catch (\Exception $e) {
            return false;
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

            $existing = $this->keysTable->find(['id' => $keyId, 'user_id' => $userId]);

            if (!$existing) {
                return false;
            }

            return $this->keysTable->setId($keyId)->update($data);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Report current usage against the key's configured limit.
     *
     * Read-only: unlike validateToken(), this does not consume a request from the
     * window and cannot itself be rejected for being over the limit, so it stays
     * usable for building a 429 response (e.g. reading `remaining` after enforcement
     * has already rejected the request).
     *
     * @param string $token API key
     * @return array Rate limit info
     */
    public function getRateLimit(string $token): array
    {
        try {
            if (!preg_match('/^sk_[a-f0-9]{48}$/', $token)) {
                return ['limit' => 0, 'used' => 0, 'remaining' => 0];
            }

            $keyHash = hash('sha256', $token);
            $keyData = $this->keysTable->find(['key_hash' => $keyHash]);

            if (!$keyData) {
                return ['limit' => 0, 'used' => 0, 'remaining' => 0];
            }

            $keyRecord = $keyData['account_api_keys'];
            $limit = (int)$keyRecord['rate_limit'];
            $windowExpired = empty($keyRecord['rate_window_started_at'])
                || strtotime($keyRecord['rate_window_started_at']) <= time() - self::RATE_LIMIT_WINDOW_SECONDS;
            $used = $windowExpired ? 0 : (int)$keyRecord['rate_window_count'];

            return [
                'limit' => $limit,
                'used' => $used,
                'remaining' => max(0, $limit - $used),
            ];
        } catch (\Exception $e) {
            return ['limit' => 0, 'used' => 0, 'remaining' => 0];
        }
    }
}
