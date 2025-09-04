<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;
use Krzysztofzylka\Hash\VersionedHasher;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;

class Authorization
{

    /**
     * Session instance
     * @var Session
     */
    private Session $session;

    /**
     * Account instance for database operations
     * @var Account
     */
    private Account $account;

    /**
     * Construct the Authorization instance
     */
    public function __construct()
    {
        $this->session = Kernel::$serviceContainer->get('kernel.session');
        $this->account = new Account();
    }

    /**
     * Check if the user is authorized
     * @return bool
     */
    public function isAuthorized(): bool
    {
        return $this->session->exists(Config::$sessionKey) && is_int($this->session->get(Config::$sessionKey));
    }

    /**
     * Get the authorized id
     * @return int
     */
    public function getAuthorizedId(): int
    {
        return (int)$this->session->get(Config::$sessionKey);
    }

    /**
     * Get the current user account data
     * @return array|null
     */
    public function getCurrentUser(): ?array
    {
        if (!$this->isAuthorized()) {
            return null;
        }

        return $this->account->find([Config::getColumn('id') => $this->getAuthorizedId()]);
    }

    /**
     * Register the user
     * @param string $username
     * @param string $password
     * @param string|null $email
     * @return bool
     * @throws DatabaseManagerException
     */
    public function register(string $username, string $password, ?string $email = null): bool
    {
        if (Config::isUsernameAuth()) {
            if (empty(trim($username))) {
                throw new InvalidArgumentException('Username cannot be empty');
            }

            if ($this->account->userExists($username)) {
                throw new InvalidArgumentException('Username already exists');
            }
        } elseif (Config::isEmailAuth()) {
            if (empty(trim($email))) {
                throw new InvalidArgumentException('Email cannot be empty');
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Invalid email format');
            }

            if ($this->account->emailExists($email)) {
                throw new InvalidArgumentException('Email already exists');
            }
        }

        if (strlen($password) < 6) {
            throw new InvalidArgumentException('Password must be at least 6 characters long');
        }

        $password = VersionedHasher::create($password);

        $data = [
            Config::getColumn('username') => $username,
            Config::getColumn('password') => $password,
        ];

        if ($email) {
            $data[Config::getColumn('email')] = $email;
        }

        $data[Config::getColumn('active')] = Config::isActivationRequired() ? 0 : 1;

        return $this->account->insert($data);
    }

    /**
     * Login the user
     * @param string $login
     * @param string $password
     * @return bool
     * @throws DatabaseManagerException
     */
    public function login(string $login, string $password): bool
    {
        if (empty(trim($login))) {
            $field = Config::isEmailAuth() ? 'Email' : 'Username';
            throw new InvalidArgumentException($field . ' cannot be empty');
        }

        if (empty($password)) {
            throw new InvalidArgumentException('Password cannot be empty');
        }

        $conditions = [];

        if (Config::isEmailAuth()) {
            if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Invalid email format');
            }

            $conditions[Config::getColumn('email')] = $login;
        } else {
            $conditions[Config::getColumn('username')] = $login;
        }

        $account = $this->account->find($conditions);

        if (!$account) {
            return false;
        }

        if (!VersionedHasher::verify($account[Config::$tableName][Config::getColumn('password')], $password)) {
            return false;
        }

        if (Config::isActivationRequired() && empty($account[Config::$tableName][Config::getColumn('active')])) {
            return false;
        }

        $this->account->setId($account[Config::$tableName][Config::getColumn('id')]);

        if (VersionedHasher::needsRehash($account[Config::$tableName][Config::getColumn('password')])) {
            $this->account->changePassword($password);
        }

        $this->session->set(Config::$sessionKey, $account[Config::$tableName][Config::getColumn('id')]);

        return true;
    }

    /**
     * Logout the user
     * @return void
     */
    public function logout(): void
    {
        $this->session->remove(Config::$sessionKey);
    }

    /**
     * Check if user has specific role
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->userHasRole($userId);
    }

    /**
     * Check if user has specific permission
     * @param string $permissionName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasPermission(string $permissionName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userRoles = $this->getUserRoles();

        foreach ($userRoles as $roleData) {
            $role = new Role($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);
            $permissions = $role->getPermissions();

            foreach ($permissions as $permission) {
                if ($permission[Config::getPermissionTableName()][Config::getPermissionColumn('name')] === $permissionName) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has any of the specified roles
     * @param array $roleNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAnyRole(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if ($this->hasRole($roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified roles
     * @param array $roleNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAllRoles(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if (!$this->hasRole($roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if user has any of the specified permissions
     * @param array $permissionNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAnyPermission(array $permissionNames): bool
    {
        foreach ($permissionNames as $permissionName) {
            if ($this->hasPermission($permissionName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified permissions
     * @param array $permissionNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAllPermissions(array $permissionNames): bool
    {
        foreach ($permissionNames as $permissionName) {
            if (!$this->hasPermission($permissionName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all roles for current user
     * @return array
     * @throws DatabaseManagerException
     */
    public function getUserRoles(): array
    {
        if (!$this->isAuthorized()) {
            return [];
        }

        $userId = $this->getAuthorizedId();
        $userRolesTable = new Table(Config::getUserRoleTableName());

        $userRoles = $userRolesTable->findAll([
            Config::getUserRoleColumn('user_id') => $userId
        ]) ?? [];

        $roles = [];
        $rolesTable = new Table(Config::getRoleTableName());

        foreach ($userRoles as $userRole) {
            $roleId = $userRole[Config::getUserRoleTableName()][Config::getUserRoleColumn('role_id')];
            $role = $rolesTable->find([Config::getRoleColumn('id') => $roleId]);

            if ($role) {
                $roles[] = $role;
            }
        }

        return $roles;
    }

    /**
     * Get all permissions for current user
     * @return array
     * @throws DatabaseManagerException
     */
    public function getUserPermissions(): array
    {
        if (!$this->isAuthorized()) {
            return [];
        }

        $userRoles = $this->getUserRoles();
        $permissions = [];

        foreach ($userRoles as $roleData) {
            $role = new Role($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);
            $rolePermissions = $role->getPermissions();

            foreach ($rolePermissions as $permission) {
                $permissionName = $permission[Config::getPermissionTableName()][Config::getPermissionColumn('name')];

                if (!in_array($permissionName, array_column($permissions, Config::getPermissionTableName() . '.' . Config::getPermissionColumn('name')))) {
                    $permissions[] = $permission;
                }
            }
        }

        return $permissions;
    }

    /**
     * Assign role to current user
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->assignToUser($userId);
    }

    /**
     * Remove role from current user
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->removeFromUser($userId);
    }

}
