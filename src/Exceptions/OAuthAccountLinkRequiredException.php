<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\Exceptions;

use RuntimeException;

/** Raised when an OAuth e-mail belongs to an account that was not explicitly linked. */
final class OAuthAccountLinkRequiredException extends RuntimeException
{
}
