<?php

namespace NimblePHP\Authorization;

/**
 * Security-sensitive operations that require an explicit application policy.
 */
enum PrivilegedAction: string
{

    case COMPLETE_CHALLENGE = 'authorization.challenge.complete';

    case AUTHENTICATE_AS = 'authorization.authenticate_as';

    case CREATE_PENDING_TWO_FACTOR = 'authorization.two_factor.pending.create';

    case GENERATE_TOKEN = 'authorization.token.generate';

    case MANAGE_RBAC = 'authorization.rbac.manage';

}
