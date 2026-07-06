<?php

namespace NimblePHP\Authorization\Interfaces;

/**
 * PermissionProvider Interface - Source of truth for role/permission checks
 *
 * The module ships RbacPermissionProvider (global roles/permissions from the
 * module's RBAC tables). Applications with their own permission model
 * (e.g. scoped per workspace/project) can delegate all checks - including
 * the HasRole/HasPermission attributes - to their own implementation:
 *
 * ```php
 * Config::setPermissionProvider(new MyPermissionProvider());
 * ```
 *
 * @package NimblePHP\Authorization\Interfaces
 */
interface PermissionProvider
{

    /**
     * Check if account has the role
     * @param int $accountId
     * @param string $roleName
     * @return bool
     */
    public function hasRole(int $accountId, string $roleName): bool;

    /**
     * Check if account has the permission
     * @param int $accountId
     * @param string $permissionName
     * @return bool
     */
    public function hasPermission(int $accountId, string $permissionName): bool;

}
