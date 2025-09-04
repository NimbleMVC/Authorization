<?php

namespace NimblePHP\Authorization;

class Config
{

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
        self::$columns['id'] = $_ENV['AUTHORIZATION_COLUMN_ID'] ?? 'id';
        self::$columns['username'] = $_ENV['AUTHORIZATION_COLUMN_USERNAME'] ?? 'username';
        self::$columns['email'] = $_ENV['AUTHORIZATION_COLUMN_EMAIL'] ?? 'email';
        self::$columns['password'] = $_ENV['AUTHORIZATION_COLUMN_PASSWORD'] ?? 'password';
        self::$columns['active'] = $_ENV['AUTHORIZATION_COLUMN_ACTIVE'] ?? 'active';

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

}