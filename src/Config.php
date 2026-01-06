<?php

namespace NimblePHP\Authorization;

use NimblePHP\Authorization\Interfaces\PasswordHasher;
use NimblePHP\Authorization\Hashers\DefaultPasswordHasher;

/**
 * Config class - Centralized configuration for Authorization library
 * 
 * This class manages:
 * - Authentication settings (username/email auth type)
 * - User account table configuration
 * - Column name mappings
 * - RBAC (Role-Based Access Control) settings
 * - Session key configuration
 * - Custom password hasher implementation
 * 
 * Configuration can be customized via environment variables or direct property assignment.
 * 
 * @package NimblePHP\Authorization
 */
class Config
{

    /**
     * Middleware priority
     * @var int
     */
    public static int $middlewarePriority = 255;

    /**
     * Authentication type: 'username' or 'email'
     * @var string
     */
    public static string $authType = 'username';

    /**
     * Users table name
     * @var string
     */
    public static string $tableName = 'accounts';

    /**
     * Session key for user ID
     * @var string
     */
    public static string $sessionKey = 'account_id';

    /**
     * Require account activation before login
     * @var bool
     */
    public static bool $requireActivation = false;

    /**
     * Require authentication by default for all controllers
     * @var bool
     */
    public static bool $requireAuthByDefault = false;

    /**
     * Language code for translations (en, pl, etc.)
     * @var string
     */
    public static string $language = 'en';

    // ===== Password Hashing Configuration =====

    /**
     * Password hasher implementation
     * @var PasswordHasher
     */
    private static ?PasswordHasher $passwordHasher = null;

    // ===== Rate Limiting Configuration =====

    /**
     * Enable rate limiting for login attempts (brute force protection)
     * @var bool
     */
    public static bool $rateLimitEnabled = true;

    /**
     * Maximum login attempts before lockout
     * @var int
     */
    public static int $rateLimitMaxAttempts = 5;

    /**
     * Lockout duration in seconds
     * @var int
     */
    public static int $rateLimitLockoutDuration = 900; // 15 minutes

    // ===== Two-Factor Authentication Configuration =====

    /**
     * Session key for pending 2FA user ID
     * @var string
     */
    public static string $twoFactorSessionKey = 'pending_2fa_user_id';

    /**
     * Session key for pending 2FA provider
     * @var string
     */
    public static string $twoFactorProviderSessionKey = 'pending_2fa_provider';

    /**
     * 2FA column names in the accounts table
     * @var array
     */
    public static array $twoFactorColumns = [
        'secret' => 'account_two_factor_secret',
        'provider' => 'account_two_factor_provider',
    ];

    /**
     * Array of available 2FA providers
     * @var array<string, \NimblePHP\Authorization\Interfaces\TwoFactorProvider>
     */
    private static array $twoFactorProviders = [];

    // ===== OAuth Configuration =====

    /**
     * OAuth column names in the accounts table
     * @var array
     */
    public static array $oauthColumns = [
        'id' => 'account_oauth_id',
        'provider' => 'account_oauth_provider',
    ];

    /**
     * Array of available OAuth providers
     * @var array<string, \NimblePHP\Authorization\Interfaces\OAuthProvider>
     */
    private static array $oauthProviders = [];

    // ===== Token-Based Authentication Configuration =====

    /**
     * Array of available token providers (JWT, API Keys, etc.)
     * @var array<string, \NimblePHP\Authorization\Interfaces\TokenProvider>
     */
    private static array $tokenProviders = [];

    /**
     * Column names in the table
     * @var array
     */
    public static array $columns = [
        'id' => 'id',
        'username' => 'username',
        'email' => 'email',
        'password' => 'password',
        'active' => 'active'
    ];

    /**
     * Initialize configuration from environment variables
     */
    public static function init(): void
    {
        self::$authType = $_ENV['AUTHORIZATION_TYPE'] ?? 'username';
        self::$tableName = $_ENV['AUTHORIZATION_TABLE'] ?? 'accounts';
        self::$sessionKey = $_ENV['AUTHORIZATION_SESSION_KEY'] ?? 'account_id';
        self::$requireActivation = filter_var($_ENV['AUTHORIZATION_REQUIRE_ACTIVATION'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$requireAuthByDefault = filter_var($_ENV['AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitEnabled = filter_var($_ENV['AUTHORIZATION_RATE_LIMIT_ENABLED'] ?? true, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitMaxAttempts = (int)($_ENV['AUTHORIZATION_RATE_LIMIT_MAX_ATTEMPTS'] ?? 5);
        self::$rateLimitLockoutDuration = (int)($_ENV['AUTHORIZATION_RATE_LIMIT_LOCKOUT_DURATION'] ?? 900);
        self::$language = $_ENV['AUTHORIZATION_LANGUAGE'] ?? 'en';
        self::$columns['id'] = $_ENV['AUTHORIZATION_COLUMN_ID'] ?? 'id';
        self::$columns['username'] = $_ENV['AUTHORIZATION_COLUMN_USERNAME'] ?? 'username';
        self::$columns['email'] = $_ENV['AUTHORIZATION_COLUMN_EMAIL'] ?? 'email';
        self::$columns['password'] = $_ENV['AUTHORIZATION_COLUMN_PASSWORD'] ?? 'password';
        self::$columns['active'] = $_ENV['AUTHORIZATION_COLUMN_ACTIVE'] ?? 'active';
        self::$middlewarePriority = $_ENV['AUTHORIZATION_MIDDLEWARE_PRIORITY'] ?? 255;

        // Initialize language
        Lang::setLanguage(self::$language);

        self::initRbac();
    }

    /**
     * Get column name
     * @param string $column
     * @return string
     */
    public static function getColumn(string $column): string
    {
        return self::$columns[$column] ?? $column;
    }

    /**
     * Check if authentication is through email
     * @return bool
     */
    public static function isEmailAuth(): bool
    {
        return self::$authType === 'email';
    }

    /**
     * Check if authentication is through username
     * @return bool
     */
    public static function isUsernameAuth(): bool
    {
        return self::$authType === 'username';
    }

    /**
     * Check if account activation is required
     * @return bool
     */
    public static function isActivationRequired(): bool
    {
        return self::$requireActivation;
    }

    /**
     * Check if authentication is required by default
     * @return bool
     */
    public static function isAuthRequiredByDefault(): bool
    {
        return self::$requireAuthByDefault;
    }

    // ===== RBAC Configuration =====

    /**
     * Roles table name
     * @var string
     */
    public static string $rolesTableName = 'account_roles';

    /**
     * Permissions table name
     * @var string
     */
    public static string $permissionsTableName = 'account_permissions';

    /**
     * User roles table name
     * @var string
     */
    public static string $userRolesTableName = 'account_user_roles';

    /**
     * Role permissions table name
     * @var string
     */
    public static string $rolePermissionsTableName = 'account_role_permissions';

    /**
     * Role table columns
     * @var array
     */
    public static array $roleColumns = [
        'id' => 'id',
        'name' => 'name',
        'description' => 'description',
        'created_at' => 'date_created'
    ];

    /**
     * Permission table columns
     * @var array
     */
    public static array $permissionColumns = [
        'id' => 'id',
        'name' => 'name',
        'description' => 'description',
        'group' => 'group',
        'created_at' => 'date_created'
    ];

    /**
     * User roles table columns
     * @var array
     */
    public static array $userRoleColumns = [
        'id' => 'id',
        'user_id' => 'account_id',
        'role_id' => 'role_id',
        'assigned_at' => 'date_assigned'
    ];

    /**
     * Role permissions table columns
     * @var array
     */
    public static array $rolePermissionColumns = [
        'id' => 'id',
        'role_id' => 'role_id',
        'permission_id' => 'permission_id',
        'assigned_at' => 'date_assigned'
    ];

    /**
     * Initialize RBAC configuration from environment variables
     */
    public static function initRbac(): void
    {
        self::$rolesTableName = $_ENV['AUTHORIZATION_ROLES_TABLE'] ?? 'account_roles';
        self::$permissionsTableName = $_ENV['AUTHORIZATION_PERMISSIONS_TABLE'] ?? 'account_permissions';
        self::$userRolesTableName = $_ENV['AUTHORIZATION_USER_ROLES_TABLE'] ?? 'account_user_roles';
        self::$rolePermissionsTableName = $_ENV['AUTHORIZATION_ROLE_PERMISSIONS_TABLE'] ?? 'account_role_permissions';

        // Role columns
        self::$roleColumns['id'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_ID'] ?? 'id';
        self::$roleColumns['name'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_NAME'] ?? 'name';
        self::$roleColumns['description'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_DESCRIPTION'] ?? 'description';
        self::$roleColumns['created_at'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_CREATED_AT'] ?? 'created_at';

        // Permission columns
        self::$permissionColumns['id'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_ID'] ?? 'id';
        self::$permissionColumns['name'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_NAME'] ?? 'name';
        self::$permissionColumns['description'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_DESCRIPTION'] ?? 'description';
        self::$permissionColumns['group'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_GROUP'] ?? 'group';
        self::$permissionColumns['created_at'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_CREATED_AT'] ?? 'created_at';

        // User role columns
        self::$userRoleColumns['id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ID'] ?? 'id';
        self::$userRoleColumns['user_id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_USER_ID'] ?? 'user_id';
        self::$userRoleColumns['role_id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ROLE_ID'] ?? 'role_id';
        self::$userRoleColumns['assigned_at'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ASSIGNED_AT'] ?? 'assigned_at';

        // Role permission columns
        self::$rolePermissionColumns['id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ID'] ?? 'id';
        self::$rolePermissionColumns['role_id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ROLE_ID'] ?? 'role_id';
        self::$rolePermissionColumns['permission_id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_PERMISSION_ID'] ?? 'permission_id';
        self::$rolePermissionColumns['assigned_at'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ASSIGNED_AT'] ?? 'assigned_at';
    }

    /**
     * Get roles table name
     * @return string
     */
    public static function getRoleTableName(): string
    {
        return self::$rolesTableName;
    }

    /**
     * Get permissions table name
     * @return string
     */
    public static function getPermissionTableName(): string
    {
        return self::$permissionsTableName;
    }

    /**
     * Get user roles table name
     * @return string
     */
    public static function getUserRoleTableName(): string
    {
        return self::$userRolesTableName;
    }

    /**
     * Get role permissions table name
     * @return string
     */
    public static function getRolePermissionTableName(): string
    {
        return self::$rolePermissionsTableName;
    }

    /**
     * Get role column name
     * @param string $column
     * @return string
     */
    public static function getRoleColumn(string $column): string
    {
        return self::$roleColumns[$column] ?? $column;
    }

    /**
     * Get permission column name
     * @param string $column
     * @return string
     */
    public static function getPermissionColumn(string $column): string
    {
        return self::$permissionColumns[$column] ?? $column;
    }

    /**
     * Get user role column name
     * @param string $column
     * @return string
     */
    public static function getUserRoleColumn(string $column): string
    {
        return self::$userRoleColumns[$column] ?? $column;
    }

    /**
     * Get role permission column name
     * @param string $column
     * @return string
     */
    public static function getRolePermissionColumn(string $column): string
    {
        return self::$rolePermissionColumns[$column] ?? $column;
    }

    /**
     * Check if rate limiting is enabled
     * @return bool
     */
    public static function isRateLimitEnabled(): bool
    {
        return self::$rateLimitEnabled;
    }

    /**
     * Get maximum login attempts before lockout
     * @return int
     */
    public static function getRateLimitMaxAttempts(): int
    {
        return self::$rateLimitMaxAttempts;
    }

    /**
     * Get lockout duration in seconds
     * @return int
     */
    public static function getRateLimitLockoutDuration(): int
    {
        return self::$rateLimitLockoutDuration;
    }

    /**
     * Set custom password hasher implementation
     * 
     * @param PasswordHasher $hasher Custom password hasher
     * @return void
     */
    public static function setPasswordHasher(PasswordHasher $hasher): void
    {
        self::$passwordHasher = $hasher;
    }

    /**
     * Get password hasher instance
     * 
     * Returns custom hasher if set, otherwise returns default hasher
     * 
     * @return PasswordHasher Password hasher instance
     */
    public static function getPasswordHasher(): PasswordHasher
    {
        if (self::$passwordHasher === null) {
            self::$passwordHasher = new DefaultPasswordHasher();
        }

        return self::$passwordHasher;
    }

    /**
     * Register a 2FA provider
     *
     * @param string $name Provider name (e.g., 'totp', 'email')
     * @param \NimblePHP\Authorization\Interfaces\TwoFactorProvider $provider The provider instance
     * @return void
     */
    public static function registerTwoFactorProvider(string $name, $provider): void
    {
        self::$twoFactorProviders[$name] = $provider;
    }

    /**
     * Get a 2FA provider by name
     *
     * @param string $name Provider name
     * @return \NimblePHP\Authorization\Interfaces\TwoFactorProvider|null The provider or null if not found
     */
    public static function getTwoFactorProvider(string $name)
    {
        return self::$twoFactorProviders[$name] ?? null;
    }

    /**
     * Get all registered 2FA providers
     *
     * @return array<string, \NimblePHP\Authorization\Interfaces\TwoFactorProvider>
     */
    public static function getTwoFactorProviders(): array
    {
        return self::$twoFactorProviders;
    }

    /**
     * Get 2FA secret column name
     *
     * @return string
     */
    public static function getTwoFactorSecretColumn(): string
    {
        return self::$twoFactorColumns['secret'];
    }

    /**
     * Get 2FA provider column name
     *
     * @return string
     */
    public static function getTwoFactorProviderColumn(): string
    {
        return self::$twoFactorColumns['provider'];
    }

    /**
     * Register OAuth provider
     *
     * Registers an OAuth provider implementation for use in authentication flow
     *
     * @param string $name Provider name (e.g., 'github', 'google')
     * @param \NimblePHP\Authorization\Interfaces\OAuthProvider $provider Provider instance
     * @return void
     */
    public static function registerOAuthProvider(string $name, \NimblePHP\Authorization\Interfaces\OAuthProvider $provider): void
    {
        self::$oauthProviders[$name] = $provider;
    }

    /**
     * Get OAuth provider by name
     *
     * @param string $name Provider name
     * @return \NimblePHP\Authorization\Interfaces\OAuthProvider OAuth provider instance
     * @throws \InvalidArgumentException If provider not registered
     */
    public static function getOAuthProvider(string $name): \NimblePHP\Authorization\Interfaces\OAuthProvider
    {
        if (!isset(self::$oauthProviders[$name])) {
            throw new \InvalidArgumentException("OAuth provider '{$name}' is not registered");
        }

        return self::$oauthProviders[$name];
    }

    /**
     * Get all registered OAuth providers
     *
     * @return array<string, \NimblePHP\Authorization\Interfaces\OAuthProvider>
     */
    public static function getOAuthProviders(): array
    {
        return self::$oauthProviders;
    }

    /**
     * Get OAuth column name by key
     *
     * @param string $key Column key ('id' or 'provider')
     * @return string Column name
     */
    public static function getOAuthColumn(string $key): string
    {
        return self::$oauthColumns[$key] ?? $key;
    }

    /**
     * Register token provider (JWT, API Key, etc.)
     *
     * @param string $name Provider name (e.g., 'jwt', 'api_key')
     * @param \NimblePHP\Authorization\Interfaces\TokenProvider $provider Provider instance
     * @return void
     */
    public static function registerTokenProvider(string $name, \NimblePHP\Authorization\Interfaces\TokenProvider $provider): void
    {
        self::$tokenProviders[$name] = $provider;
    }

    /**
     * Get token provider by name
     *
     * @param string $name Provider name
     * @return \NimblePHP\Authorization\Interfaces\TokenProvider Token provider instance
     * @throws \InvalidArgumentException If provider not registered
     */
    public static function getTokenProvider(string $name): \NimblePHP\Authorization\Interfaces\TokenProvider
    {
        if (!isset(self::$tokenProviders[$name])) {
            throw new \InvalidArgumentException("Token provider '{$name}' is not registered");
        }

        return self::$tokenProviders[$name];
    }

    /**
     * Get all registered token providers
     *
     * @return array<string, \NimblePHP\Authorization\Interfaces\TokenProvider>
     */
    public static function getTokenProviders(): array
    {
        return self::$tokenProviders;
    }

}
