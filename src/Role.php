<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;

/**
 * Role management class
 */
class Role
{

    /**
     * Roles table instance
     * @var Table
     */
    private Table $rolesTable;

    /**
     * Role permissions table instance
     * @var Table
     */
    private Table $rolePermissionsTable;

    /**
     * User roles table instance
     * @var Table
     */
    private Table $userRolesTable;

    /**
     * Role ID
     * @var int|null
     */
    private ?int $id;

    /**
     * Role data
     * @var array|null
     */
    private ?array $roleData;

    /**
     * Construct the Role instance
     * @param int|null $id
     */
    public function __construct(?int $id = null)
    {
        $this->rolesTable = new Table(Config::getRoleTableName());
        $this->rolePermissionsTable = new Table(Config::getRolePermissionTableName());
        $this->userRolesTable = new Table(Config::getUserRoleTableName());
        $this->setId($id);
    }

    /**
     * Set role ID
     * @param int|null $id
     * @return void
     */
    public function setId(?int $id): void
    {
        $this->id = $id;
        $this->roleData = null;

        if ($id) {
            $this->rolesTable->setId($id);
        }
    }

    /**
     * Get role ID
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * Get role data
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function getRole(): ?array
    {
        if (!$this->id) {
            return null;
        }

        if ($this->roleData === null) {
            $this->roleData = $this->rolesTable->find([Config::getRoleColumn('id') => $this->id]);
        }

        return $this->roleData;
    }

    /**
     * Create a new role
     * @param string $name
     * @param string|null $description
     * @return bool
     * @throws DatabaseManagerException
     */
    public function create(string $name, ?string $description = null): bool
    {
        if (empty(trim($name))) {
            throw new InvalidArgumentException('Role name cannot be empty');
        }

        if ($this->roleExists($name)) {
            throw new InvalidArgumentException('Role already exists');
        }

        $data = [
            Config::getRoleColumn('name') => trim($name),
            Config::getRoleColumn('created_at') => date('Y-m-d H:i:s')
        ];

        if ($description) {
            $data[Config::getRoleColumn('description')] = trim($description);
        }

        return $this->rolesTable->insert($data);
    }

    /**
     * Update role
     * @param array $data
     * @return bool
     * @throws DatabaseManagerException
     */
    public function update(array $data): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->rolesTable->update($data);
    }

    /**
     * Delete role
     * @return bool
     * @throws DatabaseManagerException
     */
    public function delete(): bool
    {
        if (!$this->id) {
            return false;
        }

        // Remove role from all users
        $this->userRolesTable->deleteByConditions([Config::getUserRoleColumn('role_id') => $this->id]);

        // Remove all permissions from role
        $this->rolePermissionsTable->deleteByConditions([Config::getRolePermissionColumn('role_id') => $this->id]);

        return $this->rolesTable->delete();
    }

    /**
     * Check if role exists by name
     * @param string $name
     * @return bool
     * @throws DatabaseManagerException
     */
    public function roleExists(string $name): bool
    {
        return $this->rolesTable->findIsset([Config::getRoleColumn('name') => $name]);
    }

    /**
     * Find role by name
     * @param string $name
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function findByName(string $name): ?array
    {
        return $this->rolesTable->find([Config::getRoleColumn('name') => $name]);
    }

    /**
     * Get all roles
     * @return array
     * @throws DatabaseManagerException
     */
    public function getAllRoles(): array
    {
        return $this->rolesTable->findAll() ?? [];
    }

    /**
     * Assign role to user
     * @param int $userId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignToUser(int $userId): bool
    {
        if (!$this->id) {
            return false;
        }

        if ($this->userHasRole($userId)) {
            return true;
        }

        return $this->userRolesTable->insert([
            Config::getUserRoleColumn('user_id') => $userId,
            Config::getUserRoleColumn('role_id') => $this->id,
            Config::getUserRoleColumn('assigned_at') => date('Y-m-d H:i:s')
        ]);
    }

    /**
     * Remove role from user
     * @param int $userId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeFromUser(int $userId): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->userRolesTable->deleteByConditions([
            Config::getUserRoleColumn('user_id') => $userId,
            Config::getUserRoleColumn('role_id') => $this->id
        ]);
    }

    /**
     * Check if user has this role
     * @param int $userId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function userHasRole(int $userId): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->userRolesTable->findIsset([
            Config::getUserRoleColumn('user_id') => $userId,
            Config::getUserRoleColumn('role_id') => $this->id
        ]);
    }

    /**
     * Get all users with this role
     * @return array
     * @throws DatabaseManagerException
     */
    public function getUsersWithRole(): array
    {
        if (!$this->id) {
            return [];
        }

        return $this->userRolesTable->findAll([
            Config::getUserRoleColumn('role_id') => $this->id
        ]) ?? [];
    }

    /**
     * Get role permissions
     * @return array
     * @throws DatabaseManagerException
     */
    public function getPermissions(): array
    {
        if (!$this->id) {
            return [];
        }

        $rolePermissions = $this->rolePermissionsTable->findAll([
            Config::getRolePermissionColumn('role_id') => $this->id
        ]) ?? [];

        $permissions = [];

        foreach ($rolePermissions as $rolePermission) {
            $permissionId = $rolePermission[Config::getRolePermissionTableName()][Config::getRolePermissionColumn('permission_id')];
            $permission = $this->getPermissionById($permissionId);

            if ($permission) {
                $permissions[] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Add permission to role
     * @param int $permissionId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function addPermission(int $permissionId): bool
    {
        if (!$this->id) {
            return false;
        }

        // Check if role already has this permission
        if ($this->hasPermission($permissionId)) {
            return true;
        }

        return $this->rolePermissionsTable->insert([
            Config::getRolePermissionColumn('role_id') => $this->id,
            Config::getRolePermissionColumn('permission_id') => $permissionId,
            Config::getRolePermissionColumn('assigned_at') => date('Y-m-d H:i:s')
        ]);
    }

    /**
     * Remove permission from role
     * @param int $permissionId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removePermission(int $permissionId): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->rolePermissionsTable->deleteByConditions([
            Config::getRolePermissionColumn('role_id') => $this->id,
            Config::getRolePermissionColumn('permission_id') => $permissionId
        ]);
    }

    /**
     * Check if role has permission
     * @param int $permissionId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasPermission(int $permissionId): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->rolePermissionsTable->findIsset([
            Config::getRolePermissionColumn('role_id') => $this->id,
            Config::getRolePermissionColumn('permission_id') => $permissionId
        ]);
    }

    /**
     * Get permission by ID
     * @param int $permissionId
     * @return array|null
     * @throws DatabaseManagerException
     */
    private function getPermissionById(int $permissionId): ?array
    {
        $permissionTable = new Table(Config::getPermissionTableName());

        return $permissionTable->find([Config::getPermissionColumn('id') => $permissionId]);
    }

    /**
     * Set permissions for role (replace all)
     * @param array $permissionIds
     * @return bool
     * @throws DatabaseManagerException
     */
    public function setPermissions(array $permissionIds): bool
    {
        if (!$this->id) {
            return false;
        }

        $this->rolePermissionsTable->deleteByConditions([Config::getRolePermissionColumn('role_id') => $this->id]);

        foreach ($permissionIds as $permissionId) {
            $this->addPermission($permissionId);
        }

        return true;
    }

    /**
     * Get roles table instance
     * @return Table
     */
    public function getRolesTable(): Table
    {
        return $this->rolesTable;
    }

    /**
     * Get user roles table instance
     * @return Table
     */
    public function getUserRolesTable(): Table
    {
        return $this->userRolesTable;
    }

    /**
     * Get role permissions table instance
     * @return Table
     */
    public function getRolePermissionsTable(): Table
    {
        return $this->rolePermissionsTable;
    }
}