<?php

return [
    'validation' => [
        'username_empty' => 'Username cannot be empty',
        'username_exists' => 'Username already exists',
        'email_empty' => 'Email cannot be empty',
        'email_invalid' => 'Invalid email format',
        'email_exists' => 'Email already exists',
        'password_empty' => 'Password cannot be empty',
        'password_too_short' => 'Password must be at least 6 characters long',
        'login_empty' => '{field} cannot be empty',
        'credentials_empty' => 'Username and password cannot be empty',
        'invalid_credentials' => 'Invalid username or password',
        'account_not_activated' => 'Account has not been activated',
        'authorization_header_missing' => 'Authorization header is missing',
        'rate_limit_exceeded' => 'Too many login attempts. Please try again in {seconds} seconds',
    ],
    'auth' => [
        'user_must_be_authenticated_2fa_enable' => 'User must be authenticated to enable 2FA',
        'user_must_be_authenticated_2fa_disable' => 'User must be authenticated to disable 2FA',
        'no_pending_2fa' => 'No pending 2FA verification',
        'user_id_mismatch' => 'User ID mismatch',
        '2fa_provider_not_configured' => '2FA provider not configured: {provider}',
        'user_not_found' => 'User not found',
        '2fa_not_enabled' => '2FA not enabled for user',
    ],
];
