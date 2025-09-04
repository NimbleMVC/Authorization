<?php

namespace NimblePHP\Authorization;

use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;
use Krzysztofzylka\Hash\VersionedHasher;
use NimblePHP\Framework\Kernel;

class Account
{

    /**
     * Account table instance
     * @var Table
     */
    private Table $account;

    /**
     * Account id
     * @var int|null
     */
    private ?int $id;

    /**
     * Construct the Account instance
     */
    public function __construct(?int $id = null)
    {
        $this->account = new Table(Config::$tableName);
        $this->setId($id ?? $this->getAuthorizedIdFromSession());
    }

    /**
     * Get authorized ID from session without creating Authorization instance
     * @return int
     */
    private function getAuthorizedIdFromSession(): int
    {
        $session = Kernel::$serviceContainer->get('kernel.session');

        return $session->exists(Config::$sessionKey) && is_int($session->get(Config::$sessionKey))
            ? (int)$session->get(Config::$sessionKey)
            : 0;
    }

    /**
     * Get the account id
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * Set the account id
     * @param int $id
     * @return void
     */
    public function setId(int $id): void
    {
        $this->id = $id;
        $this->account->setId($id);
    }

    /**
     * Check if user exists (username or email based on config)
     * @param string $identifier
     * @return bool
     * @throws DatabaseManagerException
     */
    public function userExists(string $identifier): bool
    {
        $conditions = [];

        if (Config::isEmailAuth()) {
            $conditions[Config::getColumn('email')] = $identifier;
        } else {
            $conditions[Config::getColumn('username')] = $identifier;
        }

        return $this->account->findIsset($conditions);
    }

    /**
     * Check if username exists
     * @param string $username
     * @return bool
     * @throws DatabaseManagerException
     */
    public function usernameExists(string $username): bool
    {
        return $this->account->findIsset([Config::getColumn('username') => $username]);
    }

    /**
     * Check if email exists
     * @param string $email
     * @return bool
     * @throws DatabaseManagerException
     */
    public function emailExists(string $email): bool
    {
        return $this->account->findIsset([Config::getColumn('email') => $email]);
    }

    /**
     * Get the account table instance
     * @return Table
     */
    public function getTableInstance(): Table
    {
        return $this->account;
    }

    /**
     * Get the account data
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function getAccount(): ?array
    {
        return $this->find([Config::getColumn('id') => $this->id]) ?? null;
    }

    /**
     * Find account by conditions
     * @param array $conditions
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function find(array $conditions): ?array
    {
        $result = $this->account->find($conditions);

        if (empty($result)) {
            return null;
        }

        return $result;
    }

    /**
     * Insert new account
     * @param array $data
     * @return bool
     * @throws DatabaseManagerException
     */
    public function insert(array $data): bool
    {
        return $this->account->insert($data);
    }

    /**
     * Update account data
     * @param array $data
     * @return bool
     * @throws DatabaseManagerException
     */
    public function update(array $data): bool
    {
        return $this->account->update($data);
    }

    /**
     * Change the account password
     * @param string $password
     * @return bool
     * @throws DatabaseManagerException
     */
    public function changePassword(string $password): bool
    {
        return $this->update([Config::getColumn('password') => VersionedHasher::create($password)]);
    }

    /**
     * Check if account is active
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function isActive(?int $accountId = null): bool
    {
        if (!Config::isActivationRequired()) {
            return true;
        }

        $id = $accountId ?? $this->id;

        if (!$id) {
            return false;
        }

        $account = $this->find([Config::getColumn('id') => $id]);

        if (!$account) {
            return false;
        }

        return !empty($account[Config::getColumn('active')]);
    }

    /**
     * Activate account
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function activate(?int $accountId = null): bool
    {
        $id = $accountId ?? $this->id;

        if (!$id) {
            return false;
        }

        $originalId = $this->id;
        $this->setId($id);
        $result = $this->update([Config::getColumn('active') => 1]);

        if ($originalId) {
            $this->setId($originalId);
        }

        return $result;
    }

    /**
     * Deactivate account
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function deactivate(?int $accountId = null): bool
    {
        $id = $accountId ?? $this->id;

        if (!$id) {
            return false;
        }

        $originalId = $this->id;
        $this->setId($id);
        $result = $this->update([Config::getColumn('active') => 0]);

        if ($originalId) {
            $this->setId($originalId);
        }

        return $result;
    }

    /**
     * Assign role to account
     * @param string $roleName
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignRole(string $roleName, ?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->assignToUser($userId);
    }

    /**
     * Remove role from account
     * @param string $roleName
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeRole(string $roleName, ?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->removeFromUser($userId);
    }

    /**
     * Check if account has role
     * @param string $roleName
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasRole(string $roleName, ?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->userHasRole($userId);
    }

    /**
     * Check if account has permission
     * @param string $permissionName
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasPermission(string $permissionName, ?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        // Get user's roles
        $userRoles = $this->getRoles($userId);

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
     * Get all roles for account
     * @param int|null $accountId
     * @return array
     * @throws DatabaseManagerException
     */
    public function getRoles(?int $accountId = null): array
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return [];
        }

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
     * Get all permissions for account
     * @param int|null $accountId
     * @return array
     * @throws DatabaseManagerException
     */
    public function getPermissions(?int $accountId = null): array
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return [];
        }

        $userRoles = $this->getRoles($userId);
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
     * Set roles for account (replace all)
     * @param array $roleNames
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function setRoles(array $roleNames, ?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        $userRolesTable = new Table(Config::getUserRoleTableName());
        $userRolesTable->deleteByConditions([Config::getUserRoleColumn('user_id') => $userId]);

        foreach ($roleNames as $roleName) {
            $this->assignRole($roleName, $userId);
        }

        return true;
    }

    /**
     * Clear all roles from account
     * @param int|null $accountId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function clearRoles(?int $accountId = null): bool
    {
        $userId = $accountId ?? $this->id;

        if (!$userId) {
            return false;
        }

        $userRolesTable = new Table(Config::getUserRoleTableName());

        return $userRolesTable->deleteByConditions([Config::getUserRoleColumn('user_id') => $userId]);
    }

}