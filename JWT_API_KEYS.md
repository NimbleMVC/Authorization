# JWT + API Keys Guide

Przewodnik implementacji JWT (JSON Web Tokens) i API Keys dla staeless token-based authentication.

## Spis treści

1. [JWT - JSON Web Tokens](#jwt---json-web-tokens)
   - [Konfiguracja JWT](#konfiguracja-jwt)
   - [Generowanie tokenów JWT](#generowanie-tokenów-jwt)
   - [Walidacja tokenów JWT](#walidacja-tokenów-jwt)
   - [Odświeżanie tokenów JWT](#odświeżanie-tokenów-jwt)
   - [Revocation tokenów JWT](#revocation-tokenów-jwt)

2. [API Keys](#api-keys)
   - [Konfiguracja API Keys](#konfiguracja-api-keys)
   - [Generowanie API Keys](#generowanie-api-keys)
   - [Zarządzanie API Keys](#zarządzanie-api-keys)
   - [Rate Limiting API Keys](#rate-limiting-api-keys)

3. [Autentykacja HTTP](#autentykacja-http)
4. [Best Practices](#best-practices)
5. [Troubleshooting](#troubleshooting)

## JWT - JSON Web Tokens

JWT to standard (RFC 7519) dla bezpiecznego przesyłania informacji między stronami w formie JSON obiektu.

### Konfiguracja JWT

#### 1. Rejestracja providera JWT

```php
<?php

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\JWTProvider;

// Utwórz tajny klucz (powinien być długi i bezpieczny)
$jwtSecret = $_ENV['JWT_SECRET'] ?? bin2hex(random_bytes(32));

// Rejestruj provider
$jwtProvider = new JWTProvider(
    $jwtSecret,              // Secret key (minimum 32 characters)
    'HS256',                 // Algorithm (HS256, HS512, itd.)
    3600                     // Default expiration (1 hour)
);

Config::registerTokenProvider('jwt', $jwtProvider);
```

#### 2. Zmienne środowiskowe

```env
# JWT Configuration
JWT_SECRET=your_long_secret_key_minimum_32_characters
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
```

### Generowanie tokenów JWT

#### Podczas logowania

```php
$auth = new Authorization();

// Logowanie użytkownika
if ($auth->login($username, $password)) {
    $userId = $auth->getAuthorizedId();
    
    // Generuj JWT token
    $token = $auth->generateToken($userId, 'jwt', [
        'username' => $username,
        'role' => 'user'
    ], 3600); // Expires in 1 hour
    
    // Zwróć token w odpowiedzi
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'token' => $token,
        'expires_in' => 3600
    ]);
}
```

#### Struktura JWT tokenu

JWT token składa się z 3 części oddzielonych punktami:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.signature
```

- **Header**: `{"alg":"HS256","typ":"JWT"}`
- **Payload**: `{"user_id":1,"iat":1700000000,"exp":1700003600}`
- **Signature**: HMAC-SHA256(header.payload, secret)

### Walidacja tokenów JWT

#### W middleware'ach API

```php
<?php

class APIAuthMiddleware
{
    public function handle()
    {
        $auth = new Authorization();
        
        // Pobierz token z headera
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.+)$/i', $authHeader, $matches)) {
            http_response_code(401);
            echo json_encode(['error' => 'Missing or invalid token']);
            exit;
        }
        
        $token = $matches[1];
        
        try {
            // Waliduj token
            $tokenData = $auth->validateToken($token, 'jwt');
            
            // Zaloguj użytkownika na sesji
            $auth->authenticateWithToken($token, 'jwt');
            
            // Token jest ważny - kontynuuj
            
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid or expired token']);
            exit;
        }
    }
}
```

#### Pobieranie danych z tokenu bez ustawiania sesji

```php
$auth = new Authorization();

try {
    $tokenData = $auth->validateToken($token, 'jwt');
    
    $userId = $tokenData['user_id'];
    $username = $tokenData['username'] ?? null;
    $role = $tokenData['role'] ?? null;
    
    // Użyj danych...
    
} catch (Exception $e) {
    echo 'Token invalid: ' . $e->getMessage();
}
```

### Odświeżanie tokenów JWT

Tokeny JWT mogą być odświeżane bez ponownego logowania:

```php
// Utwórz nowy token na podstawie starego
$auth = new Authorization();
$provider = $auth->getTokenProvider('jwt');

try {
    // Waliduj stary token
    $oldData = $auth->validateToken($oldToken, 'jwt');
    
    // Utwórz nowy token z tymi samymi danymi
    $newToken = $provider->refreshToken($oldToken, 3600);
    
    echo json_encode([
        'token' => $newToken,
        'expires_in' => 3600
    ]);
    
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Failed to refresh token']);
}
```

### Revocation tokenów JWT

Tokeny JWT mogą być wycofane (logout):

```php
$auth = new Authorization();

if ($auth->revokeToken($token, 'jwt')) {
    echo json_encode(['success' => true, 'message' => 'Token revoked']);
} else {
    echo json_encode(['error' => 'Failed to revoke token']);
}
```

Token jest przechowywany na blackliście w bazie danych.

## API Keys

API Keys to stacjonarne tokeny dla programistycznego dostępu do API.

### Konfiguracja API Keys

#### 1. Rejestracja providera API Keys

```php
<?php

use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\APIKeyProvider;

// Rejestruj provider
$apiKeyProvider = new APIKeyProvider();

Config::registerTokenProvider('api_key', $apiKeyProvider);
```

#### 2. Migracja bazy danych

Migracja dodaje 3 tabele:
- `account_api_keys` - przechowuje klucze API
- `account_api_key_usage` - loguje użycie kluczy
- `account_token_blacklist` - czarna lista tokenów

```php
// Uruchom migracje
php artisan migrate
```

### Generowanie API Keys

#### W panelu użytkownika

```php
<?php

class APIKeysController
{
    public function generate()
    {
        $auth = new Authorization();
        
        if (!$auth->isAuthorized()) {
            http_response_code(401);
            return;
        }
        
        $userId = $auth->getAuthorizedId();
        
        try {
            $apiKey = $auth->generateToken($userId, 'api_key', [
                'name' => $_POST['name'] ?? 'New API Key',
                'scopes' => $_POST['scopes'] ?? [],
                'rate_limit' => $_POST['rate_limit'] ?? 1000
            ], 
            365 * 24 * 3600); // 1 year expiration
            
            echo json_encode([
                'success' => true,
                'key' => $apiKey,
                'message' => 'Save this key somewhere safe. You will not be able to see it again.'
            ]);
            
        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode(['error' => $e->getMessage()]);
        }
    }
}
```

Format generowanego klucza:
```
sk_abcdef1234567890abcdef1234567890abcdef123456789012345678
```

Prefiks `sk_` oznacza "secret key".

### Zarządzanie API Keys

#### Lista kluczy użytkownika

```php
$auth = new Authorization();
$provider = $auth->getTokenProvider('api_key');
$userId = $auth->getAuthorizedId();

// Lista wszystkich kluczy użytkownika
$keys = $provider->listUserKeys($userId);

foreach ($keys as $key) {
    echo $key['name'] . ' - ' . $key['created_at'];
}
```

#### Pobranie detali klucza

```php
$provider = $auth->getTokenProvider('api_key');

$keyDetails = $provider->getKey($keyId, $userId);

if ($keyDetails) {
    echo 'Name: ' . $keyDetails['name'];
    echo 'Created: ' . $keyDetails['created_at'];
    echo 'Expires: ' . $keyDetails['expires_at'];
}
```

#### Aktualizacja klucza

```php
$provider = $auth->getTokenProvider('api_key');

$success = $provider->updateKey($keyId, $userId, [
    'name' => 'My Updated Key',
    'rate_limit' => 5000,
    'scopes' => ['read:users', 'write:posts']
]);
```

#### Revocation (deaktywacja) klucza

```php
$auth = new Authorization();

if ($auth->revokeToken($apiKey, 'api_key')) {
    echo 'API Key deactivated';
}
```

### Rate Limiting API Keys

Każdy klucz API ma limit żądań (domyślnie 1000 żądań/godzina):

```php
$provider = $auth->getTokenProvider('api_key');

$rateLimit = $provider->getRateLimit($apiKey);

echo 'Limit: ' . $rateLimit['limit'];        // 1000
echo 'Used: ' . $rateLimit['used'];          // 234
echo 'Remaining: ' . $rateLimit['remaining']; // 766
```

#### Implementacja rate limiting w middleware

```php
<?php

class APIRateLimitMiddleware
{
    public function handle()
    {
        $auth = new Authorization();
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (preg_match('/Bearer\s+(.+)$/i', $authHeader, $matches)) {
            $token = $matches[1];
            $provider = $auth->getTokenProvider('api_key');
            
            $rateLimit = $provider->getRateLimit($token);
            
            if ($rateLimit['remaining'] <= 0) {
                http_response_code(429);
                echo json_encode([
                    'error' => 'Rate limit exceeded',
                    'retry_after' => 3600
                ]);
                exit;
            }
            
            // Dodaj informacje o rate limit do headera
            header('X-RateLimit-Limit: ' . $rateLimit['limit']);
            header('X-RateLimit-Used: ' . $rateLimit['used']);
            header('X-RateLimit-Remaining: ' . $rateLimit['remaining']);
        }
    }
}
```

## Autentykacja HTTP

### HTTP Bearer Token

Standardowy sposób przesyłania JWT w żądaniach HTTP:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" https://api.example.com/api/users
```

```php
// W aplikacji
$token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (preg_match('/Bearer\s+(.+)$/i', $token, $matches)) {
    $jwtToken = $matches[1];
    // Waliduj token
}
```

### Custom Header

Możesz też użyć custom headera dla API Key:

```bash
curl -H "X-API-Key: YOUR_API_KEY" https://api.example.com/api/users
```

```php
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';

if (!empty($apiKey)) {
    $auth = new Authorization();
    try {
        $auth->validateToken($apiKey, 'api_key');
        // Klucz jest ważny
    } catch (Exception $e) {
        http_response_code(401);
    }
}
```

## Best Practices

### JWT

1. **Secret Key Security**
   - Użyj długiego, losowego klucza (minimum 32 znaki)
   - Przechowuj w zmiennych środowiskowych
   - Nigdy nie commituj do Git'a

2. **Token Expiration**
   - Krótki czas wygaśnięcia (15-60 minut)
   - Zaimplementuj refresh token flow
   - Wymuś ponowne logowanie dla wrażliwych operacji

3. **Token Storage**
   - Przechowuj w httpOnly cookies lub secure storage
   - Nigdy nie przechowuj w localStorage (podatne na XSS)

4. **Token Validation**
   - Zawsze waliduj na serwerze
   - Sprawdzaj ekspirację
   - Sprawdzaj sygnaturę

### API Keys

1. **Key Generation**
   - Generuj losowe klucze (minimum 48 znaków)
   - Używaj prefiksu (`sk_`) dla identyfikacji
   - Nie pokazuj pełnego klucza po utworzeniu

2. **Key Rotation**
   - Zachęcaj użytkowników do regularnego rotowania kluczy
   - Pozwól na jednoczesne użycie wielu kluczy
   - Ustaw daty wygaśnięcia

3. **Scopes**
   - Implementuj scopes dla granularnej kontroli dostępu
   - Ograniczaj uprawnienia do minimum
   - Loguj operacje wykonane kluczem

4. **Rate Limiting**
   - Ustaw rozumne limity żądań
   - Monitoruj anomalną aktywność
   - Zautomatyzuj blokowanie nadużywanych kluczy

5. **Logging**
   - Loguj każde użycie klucza
   - Przechowuj IP i User-Agent
   - Alertuj o podejrzanej aktywności

## Troubleshooting

### JWT Token Validation Fails

**Błędy:**
- "Invalid JWT token format"
- "Invalid JWT signature"
- "JWT token has expired"

**Rozwiązanie:**
```php
try {
    $data = $auth->validateToken($token, 'jwt');
} catch (Exception $e) {
    // Wyświetl dokładny błąd
    error_log('JWT Error: ' . $e->getMessage());
    
    // Zwróć użytkownikowi
    echo json_encode(['error' => $e->getMessage()]);
}
```

### API Key Not Found

**Przyczyna:**
- Klucz nie istnieje
- Klucz został wycofany
- Klucz wygasł

**Rozwiązanie:**
```php
try {
    $data = $auth->validateToken($apiKey, 'api_key');
} catch (Exception $e) {
    if ($e->getMessage() === 'API key is inactive') {
        echo 'This API key has been deactivated';
    } else if ($e->getMessage() === 'API key has expired') {
        echo 'This API key has expired. Please generate a new one.';
    }
}
```

### Rate Limit Exceeded

**Rozwiązanie:**
```php
$provider = $auth->getTokenProvider('api_key');
$rateLimit = $provider->getRateLimit($apiKey);

if ($rateLimit['remaining'] == 0) {
    http_response_code(429);
    header('Retry-After: 3600');
    echo 'Rate limit exceeded. Try again in 1 hour.';
}
```

### Secret Key Too Short

**Błąd:**
```
Secret key must be at least 32 characters long for security
```

**Rozwiązanie:**
```php
$secret = bin2hex(random_bytes(32)); // 64 characters hex
$provider = new JWTProvider($secret);
```

## Przykład Full API z JWT

```php
<?php

// bootstrap.php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Providers\JWTProvider;
use NimblePHP\Authorization\Providers\APIKeyProvider;

// Rejestruj providery
$jwtProvider = new JWTProvider($_ENV['JWT_SECRET'], 'HS256', 3600);
Config::registerTokenProvider('jwt', $jwtProvider);

$apiKeyProvider = new APIKeyProvider();
Config::registerTokenProvider('api_key', $apiKeyProvider);

// login.php
if ($_POST) {
    $auth = new Authorization();
    
    if ($auth->login($_POST['username'], $_POST['password'])) {
        $userId = $auth->getAuthorizedId();
        $token = $auth->generateToken($userId, 'jwt');
        
        http_response_code(200);
        echo json_encode(['token' => $token]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
    }
}

// api_protected_endpoint.php
$auth = new Authorization();
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (!preg_match('/Bearer\s+(.+)$/i', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing token']);
    exit;
}

try {
    $tokenData = $auth->validateToken($matches[1], 'jwt');
    $userId = $tokenData['user_id'];
    
    // Token jest ważny - wykonaj operację
    echo json_encode(['message' => 'Hello user ' . $userId]);
    
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token']);
}
```

