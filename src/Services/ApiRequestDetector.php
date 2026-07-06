<?php

namespace NimblePHP\Authorization\Services;

use NimblePHP\Authorization\Config;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Request;

/**
 * ApiRequestDetector - Decides whether the current request expects a JSON response
 *
 * Signal cascade, strongest first:
 * 1. Config::$apiRequestDetector callable (null result = keep checking)
 * 2. Configured path prefixes (AUTHORIZATION_API_PATHS)
 * 3. Accept header containing application/json (and not preferring text/html)
 * 4. Request Content-Type application/json
 * 5. X-Requested-With: XMLHttpRequest (when AUTHORIZATION_TREAT_AJAX_AS_API)
 * 6. Fallback: false (web behaviour)
 *
 * @package NimblePHP\Authorization\Services
 */
class ApiRequestDetector
{

    /**
     * Check if the current request should be treated as an API request
     * @param Request|null $request
     * @return bool
     */
    public static function isApiRequest(?Request $request = null): bool
    {
        $request ??= Kernel::$serviceContainer->get('kernel.request');

        if (is_callable(Config::$apiRequestDetector)) {
            $result = (Config::$apiRequestDetector)($request);

            if (is_bool($result)) {
                return $result;
            }
        }

        $uri = $request->getUri();

        foreach (Config::$apiPaths as $prefix) {
            if ($prefix !== '' && str_starts_with($uri, $prefix)) {
                return true;
            }
        }

        $accept = strtolower((string)$request->getHeader('Accept'));

        if (str_contains($accept, 'application/json')) {
            $htmlPosition = strpos($accept, 'text/html');

            if ($htmlPosition === false || strpos($accept, 'application/json') < $htmlPosition) {
                return true;
            }
        }

        $contentType = strtolower((string)$request->getHeader('Content-Type'));

        if (str_contains($contentType, 'application/json')) {
            return true;
        }

        if (Config::$treatAjaxAsApi && $request->isAjax()) {
            return true;
        }

        return false;
    }

}
