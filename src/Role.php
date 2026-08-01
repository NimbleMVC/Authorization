<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Events\RoleAssignedEvent;
use NimblePHP\Authorization\Events\RolePermissionChangedEvent;
use NimblePHP\Authorization\Events\RoleRemovedEvent;
use NimblePHP\Authorization\Services\PrivilegedOperationGate;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Translation\Translation;

/**
 * Role class - Manages user roles and role-based access control
 * 
 * This class provides methods for:
 * - Role creation, update and deletion
 * - Role assignment to users
 * - Permission management for roles
 * - Role lookups and retrieval
 * - User role queries
 * 
 * @package NimblePHP\Authorization
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
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function create(string $name, ?string $description = null, ?object $evidence = null): bool
    {
        return $this->privileged(
            null,
            ['operation' => 'role.create', 'role' => $name],
            $evidence,
            function () use ($name, $description): bool {
                if (empty(trim($name))) {
                    throw new InvalidArgumentException(Translation::getInstance()->translate('module.authorization.errors.role_name_empty'));
                }

                if ($this->roleExists($name)) {
                    throw new InvalidArgumentException(Translation::getInstance()->translate('module.authorization.errors.role_already_exists'));
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
        );
    }

    /**
     * Update role
     * @param array $data
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function update(array $data, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            null,
            ['operation' => 'role.update', 'role_id' => $this->id],
            $evidence,
            fn(): bool => $this->rolesTable->update($data)
        );
    }

    /**
     * Delete role
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function delete(?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            null,
            ['operation' => 'role.delete', 'role_id' => $this->id],
            $evidence,
            function (): bool {
                $this->userRolesTable->deleteByConditions([Config::getUserRoleColumn('role_id') => $this->id]);
                $this->rolePermissionsTable->deleteByConditions([Config::getRolePermissionColumn('role_id') => $this->id]);

                return $this->rolesTable->delete();
            }
        );
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
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignToUser(int $userId, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            $userId,
            ['operation' => 'role.assign', 'role_id' => $this->id],
            $evidence,
            function () use ($userId): bool {
                if ($this->userHasRole($userId)) {
                    return true;
                }

                $result = $this->userRolesTable->insert([
                    Config::getUserRoleColumn('user_id') => $userId,
                    Config::getUserRoleColumn('role_id') => $this->id,
                    Config::getUserRoleColumn('assigned_at') => date('Y-m-d H:i:s')
                ]);

                if ($result) {
                    Kernel::dispatchEvent(new RoleAssignedEvent($userId, (string)$this->getRoleName()));
                }

                return $result;
            }
        );
    }

    /**
     * Remove role from user
     * @param int $userId
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeFromUser(int $userId, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            $userId,
            ['operation' => 'role.remove', 'role_id' => $this->id],
            $evidence,
            function () use ($userId): bool {
                $hadRole = $this->userHasRole($userId);
                $result = $this->userRolesTable->deleteByConditions([
                    Config::getUserRoleColumn('user_id') => $userId,
                    Config::getUserRoleColumn('role_id') => $this->id
                ]);

                if ($result && $hadRole) {
                    Kernel::dispatchEvent(new RoleRemovedEvent($userId, (string)$this->getRoleName()));
                }

                return $result;
            }
        );
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
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function addPermission(int $permissionId, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            null,
            ['operation' => 'role.permission.add', 'role_id' => $this->id, 'permission_id' => $permissionId],
            $evidence,
            function () use ($permissionId): bool {
                if ($this->hasPermission($permissionId)) {
                    return true;
                }

                $result = $this->rolePermissionsTable->insert([
                    Config::getRolePermissionColumn('role_id') => $this->id,
                    Config::getRolePermissionColumn('permission_id') => $permissionId,
                    Config::getRolePermissionColumn('assigned_at') => date('Y-m-d H:i:s')
                ]);

                if ($result) {
                    Kernel::dispatchEvent(new RolePermissionChangedEvent((int)$this->id, $this->getRoleName()));
                }

                return $result;
            }
        );
    }

    /**
     * Remove permission from role
     * @param int $permissionId
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removePermission(int $permissionId, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            null,
            ['operation' => 'role.permission.remove', 'role_id' => $this->id, 'permission_id' => $permissionId],
            $evidence,
            function () use ($permissionId): bool {
                $result = $this->rolePermissionsTable->deleteByConditions([
                    Config::getRolePermissionColumn('role_id') => $this->id,
                    Config::getRolePermissionColumn('permission_id') => $permissionId
                ]);

                if ($result) {
                    Kernel::dispatchEvent(new RolePermissionChangedEvent((int)$this->id, $this->getRoleName()));
                }

                return $result;
            }
        );
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
     * @param object|null $evidence Application-owned proof verified by the configured policy
     * @return bool
     * @throws DatabaseManagerException
     */
    public function setPermissions(array $permissionIds, ?object $evidence = null): bool
    {
        if (!$this->id) {
            return false;
        }

        return $this->privileged(
            null,
            ['operation' => 'role.permissions.replace', 'role_id' => $this->id],
            $evidence,
            function () use ($permissionIds, $evidence): bool {
                $this->rolePermissionsTable->deleteByConditions([Config::getRolePermissionColumn('role_id') => $this->id]);
                Kernel::dispatchEvent(new RolePermissionChangedEvent((int)$this->id, $this->getRoleName()));

                foreach ($permissionIds as $permissionId) {
                    $this->addPermission($permissionId, $evidence);
                }

                return true;
            }
        );
    }

    /**
     * @template T
     * @param array<string, mixed> $context
     * @param callable(): T $callback
     * @return T
     */
    private function privileged(
        ?int $targetAccountId,
        array $context,
        ?object $evidence,
        callable $callback
    ): mixed {
        return PrivilegedOperationGate::execute(
            new PrivilegedOperation(
                PrivilegedAction::MANAGE_RBAC,
                null,
                $targetAccountId,
                $context,
                $evidence
            ),
            $callback
        );
    }

    /**
     * Get the role name for event payloads
     * @return string|null
     */
    private function getRoleName(): ?string
    {
        $role = $this->getRole();

        return $role[Config::getRoleTableName()][Config::getRoleColumn('name')] ?? null;
    }

}
