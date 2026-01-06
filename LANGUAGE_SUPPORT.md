# Language Support (Internationalization)

The Authorization library supports multiple languages for validation and error messages.

## Supported Languages

- **en** (English) - Default
- **pl** (Polish)

## Configuration

### Using Environment Variable

Set the language in your `.env` file:

```env
AUTHORIZATION_LANGUAGE=pl
```

### Programmatically

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Lang;

// Set during initialization
Config::$language = 'pl';
Config::init(); // This will automatically set the language

// Or set directly
Lang::setLanguage('pl');
```

## Available Translation Keys

### Validation Messages

- `validation.username_empty` - Username cannot be empty
- `validation.username_exists` - Username already exists
- `validation.email_empty` - Email cannot be empty
- `validation.email_invalid` - Invalid email format
- `validation.email_exists` - Email already exists
- `validation.password_empty` - Password cannot be empty
- `validation.password_too_short` - Password must be at least 6 characters long
- `validation.login_empty` - Login field cannot be empty
- `validation.credentials_empty` - Username and password cannot be empty
- `validation.invalid_credentials` - Invalid username or password
- `validation.account_not_activated` - Account has not been activated
- `validation.authorization_header_missing` - Authorization header is missing
- `validation.rate_limit_exceeded` - Too many login attempts (with seconds placeholder)

### Authentication Messages

- `auth.user_must_be_authenticated_2fa_enable` - User must be authenticated to enable 2FA
- `auth.user_must_be_authenticated_2fa_disable` - User must be authenticated to disable 2FA
- `auth.no_pending_2fa` - No pending 2FA verification
- `auth.user_id_mismatch` - User ID mismatch
- `auth.2fa_provider_not_configured` - 2FA provider not configured
- `auth.user_not_found` - User not found
- `auth.2fa_not_enabled` - 2FA not enabled for user

## Adding New Languages

To add a new language:

1. Create a new language file in `src/Lang/` directory (e.g., `de.php` for German)
2. Copy the structure from `en.php` or `pl.php`
3. Translate all messages
4. Set the language in your configuration

Example `src/Lang/de.php`:

```php
<?php

return [
    'validation' => [
        'username_empty' => 'Benutzername darf nicht leer sein',
        'username_exists' => 'Benutzername existiert bereits',
        // ... more translations
    ],
    'auth' => [
        'user_must_be_authenticated_2fa_enable' => 'Benutzer muss authentifiziert sein, um 2FA zu aktivieren',
        // ... more translations
    ],
];
```

## Usage in Code

The `Lang` class is used internally by the Authorization library. You can also use it in your application:

```php
use NimblePHP\Authorization\Lang;

// Get a translation
$message = Lang::get('validation.username_empty');

// Get a translation with placeholders
$message = Lang::get('validation.login_empty', ['field' => 'Email']);
// Output: "Email cannot be empty" (en) or "Email nie może być pusty" (pl)

$message = Lang::get('auth.2fa_provider_not_configured', ['provider' => 'totp']);
// Output: "2FA provider not configured: totp" (en) or "Dostawca 2FA nie jest skonfigurowany: totp" (pl)
```

## Exception Messages

All validation exceptions now use the language system. The `login()` method now throws `ValidationException` instead of returning `false` for better error handling:

```php
use NimblePHP\Authorization\Exceptions\ValidationException;

try {
    $auth->login('user@example.com', 'wrongpassword');
} catch (ValidationException $e) {
    echo $e->getMessage();
    // English: "Invalid username or password"
    // Polish: "Nieprawidłowa nazwa użytkownika lub hasło"
}

try {
    $auth->register('', 'password123');
} catch (ValidationException $e) {
    echo $e->getMessage();
    // English: "Username cannot be empty"
    // Polish: "Nazwa użytkownika nie może być pusta"
}

try {
    $auth->login('inactive@example.com', 'password123');
} catch (ValidationException $e) {
    echo $e->getMessage();
    // English: "Account has not been activated"
    // Polish: "Konto nie zostało aktywowane"
}
```

### Breaking Change

The `login()` method now throws `ValidationException` for invalid credentials instead of returning `false`. Update your code accordingly:

**Before:**
```php
if ($auth->login($email, $password)) {
    // Success
} else {
    // Could be wrong password, inactive account, or user not found
    echo "Login failed";
}
```

**After:**
```php
try {
    $auth->login($email, $password);
    // Success
} catch (ValidationException $e) {
    // Specific error message
    echo $e->getMessage();
} catch (RateLimitExceededException $e) {
    // Rate limit exceeded
    echo $e->getMessage();
}
```

## Environment Variables Summary

```env
# Set language (en, pl, or custom)
AUTHORIZATION_LANGUAGE=pl

# Other authorization settings
AUTHORIZATION_TYPE=username
AUTHORIZATION_TABLE=accounts
AUTHORIZATION_SESSION_KEY=account_id
AUTHORIZATION_REQUIRE_ACTIVATION=false
AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT=false
AUTHORIZATION_RATE_LIMIT_ENABLED=true
AUTHORIZATION_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHORIZATION_RATE_LIMIT_LOCKOUT_DURATION=900
```

## Default Language

If no language is set or the language file is not found, the system falls back to English (`en`).
