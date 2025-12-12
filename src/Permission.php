<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;

/**
 * Permission class - Manages user permissions and permission-based access control
 * 
 * This class provides methods for:
 * - Permission creation, update and deletion
 * - Permission grouping and organization
 * - Permission assignment to roles
 * - Permission lookups and retrieval
 * - Role-permission relationship management
 * 
 * @package NimblePHP\Authorization
 */
class Permission
{

    /**
     * Permissions table instance
     * @var Table
     */
    private Table $permissionsTable;

    /**
     * Permission ID
     * @var int|null
     */
    private ?int $id;

    /**
     * Permission data
     * @var array|null
     */
    private ?array $permissionData;

    /**
     * Construct the Permission instance
     * @param int|null $id
     */
    public function __construct(?int $id = null)
    {
        $this->permissionsTable = new Table(Config::getPermissionTableName());
        $this->setId($id);
    }

    /**
     * Set permission ID
     * @param int|null $id
     * @return void
     */
    public function setId(?int $id): void
    {
        $this->id = $id;
        $this->permissionData = null;

        if ($id) {
            $this->permissionsTable->setId($id);
        }
    }

    /**
     * Get permission ID
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * Get permission data
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function getPermission(): ?array
    {
        if (!$this->id) {
            return null;
        }

        if ($this->permissionData === null) {
            $this->permissionData = $this->permissionsTable->find([Config::getPermissionColumn('id') => $this->id]);
        }

        return $this->permissionData;
    }

    /**
     * Create a new permission
     * @param string $name
     * @param string|null $description
     * @param string|null $group
     * @return bool
     * @throws DatabaseManagerException
     */
    public function create(string $name, ?string $description = null, ?string $group = null): bool
    {
        if (empty(trim($name))) {
            throw new InvalidArgumentException('Permission name cannot be empty');
        }

        if ($this->permissionExists($name)) {
            throw new InvalidArgumentException('Permission already exists');
        }

        $data = [
            Config::getPermissionColumn('name') => trim($name),
            Config::getPermissionColumn('created_at') => date('Y-m-d H:i:s')
        ];

        if ($description) {
            $data[Config::getPermissionColumn('description')] = trim($description);
        }

        if ($group) {
            $data[Config::getPermissionColumn('group')] = trim($group);
        }

        return $this->permissionsTable->insert($data);
    }

    /**
     * Update permission
     * @param array $data
     * @return bool
     * @throws DatabaseManagerException
     */
    public function update(array $data): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->permissionsTable->update($data);
    }

    /**
     * Delete permission
     * @return bool
     * @throws DatabaseManagerException
     */
    public function delete(): bool
    {
        if (!$this->id) {
            return false;
        }

        // Remove permission from all roles
        $rolePermissionsTable = new Table(Config::getRolePermissionTableName());
        $rolePermissionsTable->deleteByConditions([Config::getRolePermissionColumn('permission_id') => $this->id]);

        return $this->permissionsTable->delete();
    }

    /**
     * Check if permission exists by name
     * @param string $name
     * @return bool
     * @throws DatabaseManagerException
     */
    public function permissionExists(string $name): bool
    {
        return $this->permissionsTable->findIsset([Config::getPermissionColumn('name') => $name]);
    }

    /**
     * Find permission by name
     * @param string $name
     * @return array|null
     * @throws DatabaseManagerException
     */
    public function findByName(string $name): ?array
    {
        return $this->permissionsTable->find([Config::getPermissionColumn('name') => $name]);
    }

    /**
     * Get all permissions
     * @return array
     * @throws DatabaseManagerException
     */
    public function getAllPermissions(): array
    {
        return $this->permissionsTable->findAll() ?? [];
    }

    /**
     * Get permissions by group
     * @param string $group
     * @return array
     * @throws DatabaseManagerException
     */
    public function getPermissionsByGroup(string $group): array
    {
        return $this->permissionsTable->findAll([Config::getPermissionColumn('group') => $group]) ?? [];
    }

    /**
     * Get all permission groups
     * @return array
     * @throws DatabaseManagerException
     */
    public function getPermissionGroups(): array
    {
        $permissions = $this->getAllPermissions();
        $groups = [];

        foreach ($permissions as $permission) {
            $group = $permission[Config::getPermissionTableName()][Config::getPermissionColumn('group')] ?? 'default';
            if (!in_array($group, $groups)) {
                $groups[] = $group;
            }
        }

        return $groups;
    }

    /**
     * Get roles that have this permission
     * @return array
     * @throws DatabaseManagerException
     */
    public function getRolesWithPermission(): array
    {
        if (!$this->id) {
            return [];
        }

        $rolePermissionsTable = new Table(Config::getRolePermissionTableName());
        $rolePermissions = $rolePermissionsTable->findAll([
            Config::getRolePermissionColumn('permission_id') => $this->id
        ]) ?? [];

        $roles = [];
        $rolesTable = new Table(Config::getRoleTableName());

        foreach ($rolePermissions as $rolePermission) {
            $roleId = $rolePermission[Config::getRolePermissionTableName()][Config::getRolePermissionColumn('role_id')];
            $role = $rolesTable->find([Config::getRoleColumn('id') => $roleId]);

            if ($role) {
                $roles[] = $role;
            }
        }

        return $roles;
    }

    /**
     * Check if permission is assigned to role
     * @param int $roleId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function isAssignedToRole(int $roleId): bool
    {
        if (!$this->id) {
            return false;
        }

        $rolePermissionsTable = new Table(Config::getRolePermissionTableName());

        return $rolePermissionsTable->findIsset([
            Config::getRolePermissionColumn('role_id') => $roleId,
            Config::getRolePermissionColumn('permission_id') => $this->id
        ]);
    }

    /**
     * Assign permission to role
     * @param int $roleId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignToRole(int $roleId): bool
    {
        if (!$this->id) {
            return false;
        }

        if ($this->isAssignedToRole($roleId)) {
            return true;
        }

        $rolePermissionsTable = new Table(Config::getRolePermissionTableName());

        return $rolePermissionsTable->insert([
            Config::getRolePermissionColumn('role_id') => $roleId,
            Config::getRolePermissionColumn('permission_id') => $this->id,
            Config::getRolePermissionColumn('assigned_at') => date('Y-m-d H:i:s')
        ]);
    }

    /**
     * Remove permission from role
     * @param int $roleId
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeFromRole(int $roleId): bool
    {
        if (!$this->id) {
            return false;
        }

        $rolePermissionsTable = new Table(Config::getRolePermissionTableName());

        return $rolePermissionsTable->deleteByConditions([
            Config::getRolePermissionColumn('role_id') => $roleId,
            Config::getRolePermissionColumn('permission_id') => $this->id
        ]);
    }

    /**
     * Get permissions table instance
     * @return Table
     */
    public function getPermissionsTable(): Table
    {
        return $this->permissionsTable;
    }

}