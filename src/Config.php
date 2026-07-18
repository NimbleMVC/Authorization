<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use NimblePHP\Authorization\Handlers\ExceptionUnauthorizedHandler;
use NimblePHP\Authorization\Interfaces\OAuthProvider;
use NimblePHP\Authorization\Interfaces\PasswordHasher;
use NimblePHP\Authorization\Hashers\DefaultPasswordHasher;
use NimblePHP\Authorization\Interfaces\PermissionProvider;
use NimblePHP\Authorization\Interfaces\RateLimiterStorage;
use NimblePHP\Authorization\Interfaces\TokenProvider;
use NimblePHP\Authorization\Interfaces\TwoFactorProvider;
use NimblePHP\Authorization\Interfaces\UnauthorizedHandler;
use NimblePHP\Authorization\Providers\RbacPermissionProvider;
use NimblePHP\Authorization\Storages\DatabaseRateLimiterStorage;
use NimblePHP\Authorization\Storages\SessionRateLimiterStorage;

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
     * Priority of the AfterAttributesControllerEvent listener (access control)
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

    /** Session key containing the credential epoch captured at login. */
    public static string $authEpochSessionKey = 'account_auth_epoch';

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
     * Manage database schema (run module migrations)
     *
     * Set to false when the application ships its own accounts/RBAC schema
     * ("bring your own schema") - the module then only reads/writes tables
     * configured via table/column settings.
     * @var bool
     */
    public static bool $manageSchema = true;

    /**
     * Regenerate session id when the authenticated account changes (session fixation protection)
     * @var bool
     */
    public static bool $regenerateSessionOnLogin = true;

    // ===== Unauthorized Request Handling =====

    /**
     * Login page URL used by WebUnauthorizedHandler
     * @var string
     */
    public static string $loginUrl = '/login';

    /**
     * Session key for the URL to return to after login
     * @var string
     */
    public static string $returnUrlSessionKey = 'return_url';

    /**
     * URI prefixes treated as API requests (JSON 401 instead of redirect)
     * @var string[]
     */
    public static array $apiPaths = [];

    /**
     * Treat AJAX requests (X-Requested-With: XMLHttpRequest) as API requests
     * @var bool
     */
    public static bool $treatAjaxAsApi = true;

    /**
     * Custom API request detector: fn(Request $request): ?bool
     * (null = undecided, continue with the built-in signal cascade)
     * @var callable|null
     */
    public static $apiRequestDetector = null;

    /**
     * Custom JSON payload factory for 401 responses: fn(Request $request): array
     * @var callable|null
     */
    public static $unauthorizedJsonPayload = null;

    /**
     * Handler invoked when an unauthenticated request hits a protected action
     * @var UnauthorizedHandler|null
     */
    private static ?UnauthorizedHandler $unauthorizedHandler = null;

    /**
     * Source of truth for role/permission checks (attributes, Authorization::hasRole/hasPermission)
     * @var PermissionProvider|null
     */
    private static ?PermissionProvider $permissionProvider = null;

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

    /**
     * Also track failed attempts per client IP (REMOTE_ADDR)
     * @var bool
     */
    public static bool $rateLimitTrackIp = false;

    /**
     * Table name for DatabaseRateLimiterStorage
     * @var string
     */
    public static string $rateLimitTableName = 'account_rate_limits';

    /**
     * Rate limiter storage backend
     * @var RateLimiterStorage|null
     */
    private static ?RateLimiterStorage $rateLimiterStorage = null;

    // ===== Remember-Me Configuration =====

    /**
     * Enable persistent "remember me" login tokens
     * @var bool
     */
    public static bool $rememberMeEnabled = false;

    /**
     * Remember-me cookie name
     * @var string
     */
    public static string $rememberMeCookieName = 'remember_token';

    /**
     * Remember-me token lifetime in seconds
     * @var int
     */
    public static int $rememberMeLifetime = 2592000; // 30 days

    /**
     * Table name for remember-me tokens
     * @var string
     */
    public static string $rememberMeTableName = 'account_remember_tokens';

    /**
     * Minimum age (seconds) a remember-me token must reach before it is
     * rotated again. Rotating on literally every use is a single-use-token
     * race: a page load fires several concurrent requests (assets, AJAX)
     * carrying the same not-yet-rotated cookie value; the first to be
     * processed rotates it, and every other concurrent request then finds
     * the selector already deleted and clears the user's cookie, logging
     * them out well before the token's real lifetime. Throttling rotation
     * means a realistic burst of concurrent requests (milliseconds apart)
     * shares the same still-valid token instead of racing to replace it,
     * while rotation still happens periodically for theft-detection.
     * @var int
     */
    public static int $rememberMeRotationInterval = 300; // 5 minutes

    // ===== Two-Factor Authentication Configuration =====

    /**
     * Session key for pending challenge account ID (requireChallenge mechanism)
     * @var string
     */
    public static string $challengeSessionKey = 'pending_challenge_account_id';

    /**
     * Session key for pending challenge name
     * @var string
     */
    public static string $challengeNameSessionKey = 'pending_challenge_name';

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
     * Table containing hashed, single-use recovery codes.
     * @var string
     */
    public static string $recoveryCodeTableName = 'account_two_factor_recovery_codes';

    /**
     * Recovery-code validity period in seconds.
     * @var int
     */
    public static int $recoveryCodeLifetime = 31536000; // 1 year

    /**
     * Array of available 2FA providers
     * @var array<string, TwoFactorProvider>
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
     * Session key containing the pending, single-use OAuth flow.
     * @var string
     */
    public static string $oauthFlowSessionKey = 'oauth_flow';

    /**
     * OAuth state validity period in seconds.
     * @var int
     */
    public static int $oauthStateLifetime = 600;

    /**
     * Array of available OAuth providers
     * @var array<string, OAuthProvider>
     */
    private static array $oauthProviders = [];

    // ===== Token-Based Authentication Configuration =====

    /**
     * Array of available token providers (JWT, API Keys, etc.)
     * @var array<string, TokenProvider>
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
        'active' => 'active',
        'auth_epoch' => 'auth_epoch',
        'created_at' => 'date_created',
    ];

    /**
     * Initialize configuration from environment variables
     */
    public static function init(): void
    {
        self::$authType = $_ENV['AUTHORIZATION_TYPE'] ?? 'username';
        self::$tableName = $_ENV['AUTHORIZATION_TABLE'] ?? 'accounts';
        self::$sessionKey = $_ENV['AUTHORIZATION_SESSION_KEY'] ?? 'account_id';
        self::$authEpochSessionKey = $_ENV['AUTHORIZATION_AUTH_EPOCH_SESSION_KEY'] ?? 'account_auth_epoch';
        self::$requireActivation = filter_var($_ENV['AUTHORIZATION_REQUIRE_ACTIVATION'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$requireAuthByDefault = filter_var($_ENV['AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitEnabled = filter_var($_ENV['AUTHORIZATION_RATE_LIMIT_ENABLED'] ?? true, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitMaxAttempts = (int)($_ENV['AUTHORIZATION_RATE_LIMIT_MAX_ATTEMPTS'] ?? 5);
        self::$rateLimitLockoutDuration = (int)($_ENV['AUTHORIZATION_RATE_LIMIT_LOCKOUT_DURATION'] ?? 900);
        self::$columns['id'] = $_ENV['AUTHORIZATION_COLUMN_ID'] ?? 'id';
        self::$columns['username'] = $_ENV['AUTHORIZATION_COLUMN_USERNAME'] ?? 'username';
        self::$columns['email'] = $_ENV['AUTHORIZATION_COLUMN_EMAIL'] ?? 'email';
        self::$columns['password'] = $_ENV['AUTHORIZATION_COLUMN_PASSWORD'] ?? 'password';
        self::$columns['active'] = $_ENV['AUTHORIZATION_COLUMN_ACTIVE'] ?? 'active';
        self::$columns['auth_epoch'] = $_ENV['AUTHORIZATION_COLUMN_AUTH_EPOCH'] ?? 'auth_epoch';
        self::$columns['created_at'] = $_ENV['AUTHORIZATION_COLUMN_CREATED_AT'] ?? 'date_created';
        self::$middlewarePriority = $_ENV['AUTHORIZATION_MIDDLEWARE_PRIORITY'] ?? 255;
        self::$manageSchema = filter_var($_ENV['AUTHORIZATION_MANAGE_SCHEMA'] ?? true, FILTER_VALIDATE_BOOLEAN);
        self::$regenerateSessionOnLogin = filter_var($_ENV['AUTHORIZATION_SESSION_REGENERATE'] ?? true, FILTER_VALIDATE_BOOLEAN);
        self::$loginUrl = $_ENV['AUTHORIZATION_LOGIN_URL'] ?? '/login';
        self::$returnUrlSessionKey = $_ENV['AUTHORIZATION_RETURN_URL_SESSION_KEY'] ?? 'return_url';
        self::$apiPaths = array_values(array_filter(array_map('trim', explode(',', $_ENV['AUTHORIZATION_API_PATHS'] ?? ''))));
        self::$treatAjaxAsApi = filter_var($_ENV['AUTHORIZATION_TREAT_AJAX_AS_API'] ?? true, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitTrackIp = filter_var($_ENV['AUTHORIZATION_RATE_LIMIT_TRACK_IP'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$rateLimitTableName = $_ENV['AUTHORIZATION_RATE_LIMIT_TABLE'] ?? 'account_rate_limits';

        if (($_ENV['AUTHORIZATION_RATE_LIMIT_STORAGE'] ?? 'database') === 'session') {
            self::$rateLimiterStorage = new SessionRateLimiterStorage();
        }

        self::$rememberMeEnabled = filter_var($_ENV['AUTHORIZATION_REMEMBER_ME_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN);
        self::$rememberMeCookieName = $_ENV['AUTHORIZATION_REMEMBER_ME_COOKIE'] ?? 'remember_token';
        self::$rememberMeLifetime = (int)($_ENV['AUTHORIZATION_REMEMBER_ME_LIFETIME'] ?? 2592000);
        self::$rememberMeTableName = $_ENV['AUTHORIZATION_REMEMBER_ME_TABLE'] ?? 'account_remember_tokens';
        self::$rememberMeRotationInterval = (int)($_ENV['AUTHORIZATION_REMEMBER_ME_ROTATION_INTERVAL'] ?? 300);
        self::$recoveryCodeTableName = $_ENV['AUTHORIZATION_RECOVERY_CODE_TABLE'] ?? 'account_two_factor_recovery_codes';
        self::$recoveryCodeLifetime = (int)($_ENV['AUTHORIZATION_RECOVERY_CODE_LIFETIME'] ?? 31536000);
        self::$oauthFlowSessionKey = $_ENV['AUTHORIZATION_OAUTH_FLOW_SESSION_KEY'] ?? 'oauth_flow';
        self::$oauthStateLifetime = (int)($_ENV['AUTHORIZATION_OAUTH_STATE_LIFETIME'] ?? 600);

        self::initRbac();
    }

    /**
     * Set permission provider (delegate role/permission checks to the application)
     * @param PermissionProvider $provider
     * @return void
     */
    public static function setPermissionProvider(PermissionProvider $provider): void
    {
        self::$permissionProvider = $provider;
    }

    /**
     * Get permission provider (default: RbacPermissionProvider on module RBAC tables)
     * @return PermissionProvider
     */
    public static function getPermissionProvider(): PermissionProvider
    {
        if (self::$permissionProvider === null) {
            self::$permissionProvider = new RbacPermissionProvider();
        }

        return self::$permissionProvider;
    }

    /**
     * Set rate limiter storage backend
     * @param RateLimiterStorage $storage
     * @return void
     */
    public static function setRateLimiterStorage(RateLimiterStorage $storage): void
    {
        self::$rateLimiterStorage = $storage;
    }

    /**
     * Get rate limiter storage backend
     *
     * Default: DatabaseRateLimiterStorage (falls back to session storage with
     * a warning when the table is missing). Set AUTHORIZATION_RATE_LIMIT_STORAGE=session
     * to force the session backend.
     * @return RateLimiterStorage
     */
    public static function getRateLimiterStorage(): RateLimiterStorage
    {
        if (self::$rateLimiterStorage === null) {
            self::$rateLimiterStorage = new DatabaseRateLimiterStorage();
        }

        return self::$rateLimiterStorage;
    }

    /**
     * Get users table name
     * @return string
     */
    public static function getTableName(): string
    {
        return self::$tableName;
    }

    /**
     * Check if the module manages the database schema (migrations)
     * @return bool
     */
    public static function isSchemaManaged(): bool
    {
        return self::$manageSchema;
    }

    /**
     * Set handler for unauthenticated requests to protected actions
     * @param UnauthorizedHandler $handler
     * @return void
     */
    public static function setUnauthorizedHandler(UnauthorizedHandler $handler): void
    {
        self::$unauthorizedHandler = $handler;
    }

    /**
     * Get handler for unauthenticated requests (default: ExceptionUnauthorizedHandler)
     * @return UnauthorizedHandler
     */
    public static function getUnauthorizedHandler(): UnauthorizedHandler
    {
        if (self::$unauthorizedHandler === null) {
            self::$unauthorizedHandler = new ExceptionUnauthorizedHandler();
        }

        return self::$unauthorizedHandler;
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
     * Get session key for authenticated user ID
     * @return string
     */
    public static function getSessionKey(): string
    {
        return self::$sessionKey;
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
        'name' => 'role',
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

        // Role columns (defaults match the module migration schema)
        self::$roleColumns['id'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_ID'] ?? 'id';
        self::$roleColumns['name'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_NAME'] ?? 'role';
        self::$roleColumns['description'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_DESCRIPTION'] ?? 'description';
        self::$roleColumns['created_at'] = $_ENV['AUTHORIZATION_ROLE_COLUMN_CREATED_AT'] ?? 'date_created';

        // Permission columns
        self::$permissionColumns['id'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_ID'] ?? 'id';
        self::$permissionColumns['name'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_NAME'] ?? 'name';
        self::$permissionColumns['description'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_DESCRIPTION'] ?? 'description';
        self::$permissionColumns['group'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_GROUP'] ?? 'group';
        self::$permissionColumns['created_at'] = $_ENV['AUTHORIZATION_PERMISSION_COLUMN_CREATED_AT'] ?? 'date_created';

        // User role columns
        self::$userRoleColumns['id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ID'] ?? 'id';
        self::$userRoleColumns['user_id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_USER_ID'] ?? 'account_id';
        self::$userRoleColumns['role_id'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ROLE_ID'] ?? 'role_id';
        self::$userRoleColumns['assigned_at'] = $_ENV['AUTHORIZATION_USER_ROLE_COLUMN_ASSIGNED_AT'] ?? 'date_assigned';

        // Role permission columns
        self::$rolePermissionColumns['id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ID'] ?? 'id';
        self::$rolePermissionColumns['role_id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ROLE_ID'] ?? 'role_id';
        self::$rolePermissionColumns['permission_id'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_PERMISSION_ID'] ?? 'permission_id';
        self::$rolePermissionColumns['assigned_at'] = $_ENV['AUTHORIZATION_ROLE_PERMISSION_COLUMN_ASSIGNED_AT'] ?? 'date_assigned';
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
     * @param TwoFactorProvider $provider The provider instance
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
     * @return TwoFactorProvider|null The provider or null if not found
     */
    public static function getTwoFactorProvider(string $name)
    {
        return self::$twoFactorProviders[$name] ?? null;
    }

    /**
     * Get all registered 2FA providers
     *
     * @return array<string, TwoFactorProvider>
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
     * @param OAuthProvider $provider Provider instance
     * @return void
     */
    public static function registerOAuthProvider(string $name, OAuthProvider $provider): void
    {
        self::$oauthProviders[$name] = $provider;
    }

    /**
     * Get OAuth provider by name
     *
     * @param string $name Provider name
     * @return OAuthProvider OAuth provider instance
     * @throws InvalidArgumentException If provider not registered
     */
    public static function getOAuthProvider(string $name): OAuthProvider
    {
        if (!isset(self::$oauthProviders[$name])) {
            throw new InvalidArgumentException("OAuth provider '{$name}' is not registered");
        }

        return self::$oauthProviders[$name];
    }

    /**
     * Get all registered OAuth providers
     *
     * @return array<string, OAuthProvider>
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
     * @param TokenProvider $provider Provider instance
     * @return void
     */
    public static function registerTokenProvider(string $name, TokenProvider $provider): void
    {
        self::$tokenProviders[$name] = $provider;
    }

    /**
     * Get token provider by name
     *
     * @param string $name Provider name
     * @return TokenProvider Token provider instance
     * @throws InvalidArgumentException If provider not registered
     */
    public static function getTokenProvider(string $name): TokenProvider
    {
        if (!isset(self::$tokenProviders[$name])) {
            throw new InvalidArgumentException("Token provider '{$name}' is not registered");
        }

        return self::$tokenProviders[$name];
    }

    /**
     * Get all registered token providers
     *
     * @return array<string, TokenProvider>
     */
    public static function getTokenProviders(): array
    {
        return self::$tokenProviders;
    }

}
