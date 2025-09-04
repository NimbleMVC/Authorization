<?php

namespace NimblePHP\Authorization\Middlewares;

use NimblePHP\Authorization\Attributes\HasAllRoles;
use NimblePHP\Authorization\Attributes\HasAnyPermission;
use NimblePHP\Authorization\Attributes\HasAnyRole;
use NimblePHP\Authorization\Attributes\HasPermission;
use NimblePHP\Authorization\Attributes\HasRole;
use NimblePHP\Authorization\Attributes\NoAuth;
use NimblePHP\Authorization\Attributes\RequireAuth;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;
use NimblePHP\Framework\Middleware\Abstracts\AbstractControllerMiddleware;
use NimblePHP\Framework\Middleware\Interfaces\ControllerMiddlewareInterface;
use ReflectionMethod;

class AuthorizationMiddleware extends AbstractControllerMiddleware implements ControllerMiddlewareInterface
{

    /**
     * Check authorization based on default policy and attributes
     * @param ReflectionMethod $reflection
     * @param object $controller
     * @return void
     * @throws UnauthorizedException
     */
    public function afterAttributesController(ReflectionMethod $reflection, object $controller): void
    {
        $hasRequireAuth = !empty($reflection->getAttributes(RequireAuth::class));
        $hasNoAuth = !empty($reflection->getAttributes(NoAuth::class));
        $hasRoleAttributes = $reflection->getAttributes(HasRole::class);
        $hasPermissionAttributes = $reflection->getAttributes(HasPermission::class);
        $hasAnyRoleAttributes = $reflection->getAttributes(HasAnyRole::class);
        $hasAllRolesAttributes = $reflection->getAttributes(HasAllRoles::class);
        $hasAnyPermissionAttributes = $reflection->getAttributes(HasAnyPermission::class);
        $requireAuthByDefault = Config::isAuthRequiredByDefault();

        if ($hasNoAuth) {
            $shouldRequireAuth = false;
        } elseif ($hasRequireAuth || !empty($hasRoleAttributes) || !empty($hasPermissionAttributes) || !empty($hasAnyRoleAttributes) || !empty($hasAllRolesAttributes) || !empty($hasAnyPermissionAttributes)) {
            $shouldRequireAuth = true;
        } else {
            $shouldRequireAuth = $requireAuthByDefault;
        }

        if ($shouldRequireAuth) {
            $authorization = new Authorization();

            if (!$authorization->isAuthorized()) {
                throw new UnauthorizedException();
            }

            // Check single role attributes
            foreach ($hasRoleAttributes as $attribute) {
                $hasRoleInstance = $attribute->newInstance();
                $hasRoleInstance->handle($controller);
            }

            // Check single permission attributes
            foreach ($hasPermissionAttributes as $attribute) {
                $hasPermissionInstance = $attribute->newInstance();
                $hasPermissionInstance->handle($controller);
            }

            // Check any role attributes
            foreach ($hasAnyRoleAttributes as $attribute) {
                $hasAnyRoleInstance = $attribute->newInstance();
                $hasAnyRoleInstance->handle($controller);
            }

            // Check all roles attributes
            foreach ($hasAllRolesAttributes as $attribute) {
                $hasAllRolesInstance = $attribute->newInstance();
                $hasAllRolesInstance->handle($controller);
            }

            // Check any permission attributes
            foreach ($hasAnyPermissionAttributes as $attribute) {
                $hasAnyPermissionInstance = $attribute->newInstance();
                $hasAnyPermissionInstance->handle($controller);
            }
        }
    }

}