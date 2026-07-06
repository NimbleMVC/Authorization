<?php

namespace NimblePHP\Authorization\Listeners;

use NimblePHP\Authorization\Attributes\HasAllRoles;
use NimblePHP\Authorization\Attributes\HasAnyPermission;
use NimblePHP\Authorization\Attributes\HasAnyRole;
use NimblePHP\Authorization\Attributes\HasPermission;
use NimblePHP\Authorization\Attributes\HasRole;
use NimblePHP\Authorization\Attributes\NoAuth;
use NimblePHP\Authorization\Attributes\RequireAuth;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Events\UnauthorizedRequestEvent;
use NimblePHP\Authorization\Exceptions\UnauthorizedException;
use NimblePHP\Authorization\Services\ApiRequestDetector;
use NimblePHP\Framework\Event\Framework\AfterAttributesControllerEvent;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Request;
use ReflectionAttribute;

/**
 * Framework event listeners for the Authorization module.
 *
 * Replaces the former AuthorizationMiddleware: access control runs as a
 * listener bound to AfterAttributesControllerEvent and enforces:
 * - Default authorization policy (AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT)
 * - RequireAuth attribute
 * - NoAuth attribute (bypass authorization)
 * - Role attributes (HasRole, HasAnyRole, HasAllRoles)
 * - Permission attributes (HasPermission, HasAnyPermission)
 *
 * Unauthenticated requests are delegated to the configured UnauthorizedHandler.
 * Attributes are read with IS_INSTANCEOF, so applications may subclass them
 * (e.g. own NoAuthAction extends NoAuth).
 *
 * @package NimblePHP\Authorization\Listeners
 */
class AuthorizationEventListener
{

    /**
     * Check authorization based on default policy and attributes
     * @param AfterAttributesControllerEvent $event
     * @return void
     * @throws UnauthorizedException If authorization fails (default handler)
     */
    public function onAfterAttributesController(AfterAttributesControllerEvent $event): void
    {
        $reflection = $event->reflection;
        $controller = $event->controller;

        $hasRequireAuth = !empty($reflection->getAttributes(RequireAuth::class, ReflectionAttribute::IS_INSTANCEOF));
        $hasNoAuth = !empty($reflection->getAttributes(NoAuth::class, ReflectionAttribute::IS_INSTANCEOF));
        $hasRoleAttributes = $reflection->getAttributes(HasRole::class, ReflectionAttribute::IS_INSTANCEOF);
        $hasPermissionAttributes = $reflection->getAttributes(HasPermission::class, ReflectionAttribute::IS_INSTANCEOF);
        $hasAnyRoleAttributes = $reflection->getAttributes(HasAnyRole::class, ReflectionAttribute::IS_INSTANCEOF);
        $hasAllRolesAttributes = $reflection->getAttributes(HasAllRoles::class, ReflectionAttribute::IS_INSTANCEOF);
        $hasAnyPermissionAttributes = $reflection->getAttributes(HasAnyPermission::class, ReflectionAttribute::IS_INSTANCEOF);

        if ($hasNoAuth) {
            $shouldRequireAuth = false;
        } elseif ($hasRequireAuth || !empty($hasRoleAttributes) || !empty($hasPermissionAttributes) || !empty($hasAnyRoleAttributes) || !empty($hasAllRolesAttributes) || !empty($hasAnyPermissionAttributes)) {
            $shouldRequireAuth = true;
        } else {
            $shouldRequireAuth = Config::isAuthRequiredByDefault();
        }

        if (!$shouldRequireAuth) {
            return;
        }

        $authorization = new Authorization();

        if (!$authorization->isAuthorized()) {
            /** @var Request $request */
            $request = Kernel::$serviceContainer->get('kernel.request');
            Kernel::dispatchEvent(new UnauthorizedRequestEvent($request->getUri(), ApiRequestDetector::isApiRequest($request)));
            Config::getUnauthorizedHandler()->handle();

            return;
        }

        // Check single role attributes
        foreach ($hasRoleAttributes as $attribute) {
            $attribute->newInstance()->handle($controller);
        }

        // Check single permission attributes
        foreach ($hasPermissionAttributes as $attribute) {
            $attribute->newInstance()->handle($controller);
        }

        // Check any role attributes
        foreach ($hasAnyRoleAttributes as $attribute) {
            $attribute->newInstance()->handle($controller);
        }

        // Check all roles attributes
        foreach ($hasAllRolesAttributes as $attribute) {
            $attribute->newInstance()->handle($controller);
        }

        // Check any permission attributes
        foreach ($hasAnyPermissionAttributes as $attribute) {
            $attribute->newInstance()->handle($controller);
        }
    }

}
