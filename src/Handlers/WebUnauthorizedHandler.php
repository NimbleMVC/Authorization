<?php

namespace NimblePHP\Authorization\Handlers;

use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Interfaces\UnauthorizedHandler;
use NimblePHP\Authorization\Services\ApiRequestDetector;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Request;
use NimblePHP\Framework\Response;
use NimblePHP\Framework\Session;

/**
 * WebUnauthorizedHandler - Redirect for web requests, JSON 401 for API requests
 *
 * Web request: the current URL is stored in the session (return_url) and the
 * user is redirected to the login page with a redirectUrl query parameter.
 * API request (see ApiRequestDetector): a 401 response with a JSON payload
 * is sent; the payload can be customized via Config::$unauthorizedJsonPayload.
 *
 * Enable via:
 * ```php
 * Config::setUnauthorizedHandler(new WebUnauthorizedHandler());
 * ```
 *
 * @package NimblePHP\Authorization\Handlers
 */
class WebUnauthorizedHandler implements UnauthorizedHandler
{

    /**
     * @return void
     */
    public function handle(): void
    {
        /** @var Request $request */
        $request = Kernel::$serviceContainer->get('kernel.request');
        /** @var Response $response */
        $response = Kernel::$serviceContainer->get('kernel.response');

        if (ApiRequestDetector::isApiRequest($request)) {
            $payload = is_callable(Config::$unauthorizedJsonPayload)
                ? (Config::$unauthorizedJsonPayload)($request)
                : ['error' => 'Unauthorized'];

            $response->setStatusCode(401);
            $response->setJsonContent($payload);
            $response->send(true);

            return;
        }

        $currentUrl = $request->getUri();

        // Try transparent login with the remember-me cookie before redirecting
        if (Config::$rememberMeEnabled && (new Authorization())->loginWithRememberToken()) {
            $response->redirect($currentUrl !== '' ? $currentUrl : '/');
        }

        /** @var Session $session */
        $session = Kernel::$serviceContainer->get('kernel.session');
        $loginUrl = Config::$loginUrl;
        $currentPath = (string)(parse_url($currentUrl, PHP_URL_PATH) ?? '');
        $loginPath = (string)(parse_url($loginUrl, PHP_URL_PATH) ?? '');

        if ($currentPath !== '' && $currentPath !== '/' && $currentPath !== $loginPath) {
            $session->set(Config::$returnUrlSessionKey, $currentUrl);
            $loginUrl .= (str_contains($loginUrl, '?') ? '&' : '?') . 'redirectUrl=' . urlencode($currentUrl);
        }

        $response->redirect($loginUrl);
    }

}
