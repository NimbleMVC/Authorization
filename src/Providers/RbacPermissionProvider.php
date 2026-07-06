<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Account;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\PermissionProvider;
use NimblePHP\Authorization\Role;

/**
 * RbacPermissionProvider - Default provider using the module's RBAC tables
 *
 * Global (unscoped) role -> permission model backed by the account_roles /
 * account_permissions / account_user_roles / account_role_permissions tables.
 *
 * @package NimblePHP\Authorization\Providers
 */
class RbacPermissionProvider implements PermissionProvider
{

    /**
     * @param int $accountId
     * @param string $roleName
     * @return bool
     */
    public function hasRole(int $accountId, string $roleName): bool
    {
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->userHasRole($accountId);
    }

    /**
     * @param int $accountId
     * @param string $permissionName
     * @return bool
     */
    public function hasPermission(int $accountId, string $permissionName): bool
    {
        $account = new Account($accountId);

        foreach ($account->getRoles($accountId) as $roleData) {
            $role = new Role($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

            foreach ($role->getPermissions() as $permission) {
                if ($permission[Config::getPermissionTableName()][Config::getPermissionColumn('name')] === $permissionName) {
                    return true;
                }
            }
        }

        return false;
    }

}
