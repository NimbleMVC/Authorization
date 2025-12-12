# OAuth2 - GitHub Login Guide

Kompletny przewodnik implementacji logowania przez GitHub w aplikacji NimblePHP Authorization.

## Spis treści
1. [Rejestracja aplikacji GitHub](#rejestracja-aplikacji-github)
2. [Konfiguracja](#konfiguracja)
3. [Implementacja logowania](#implementacja-logowania)
4. [Obsługa callback'u](#obsługa-callbacku)
5. [Niestandardowe providery OAuth2](#niestandardowe-providery-oauth2)
6. [Bezpieczeństwo](#bezpieczeństwo)
7. [Troubleshooting](#troubleshooting)

## Rejestracja aplikacji GitHub

### Krok 1: Przejście do Developer Settings

1. Zaloguj się do GitHub
2. Przejdź na https://github.com/settings/developers
3. Alternatywnie: Settings → Developer settings (na dole po lewej)

### Krok 2: Tworzenie nowej OAuth App

1. Kliknij "New OAuth App"
2. Wypełnij formularz:

| Pole | Wartość | Opis |
|------|---------|------|
| **Application name** | Twoja Aplikacja | Nazwa widoczna dla użytkowników |
| **Homepage URL** | https://twoja-domena.com | URL głównej strony aplikacji |
| **Application description** | (opcjonalnie) | Opis aplikacji |
| **Authorization callback URL** | https://twoja-domena.com/oauth/github/callback | URL obsługi callbacku |

### Krok 3: Pobieranie poświadczeń

Po utworzeniu aplikacji zobaczysz:
- **Client ID** - publiczny identyfikator
- **Client Secret** - hasło (przechowaj bezpiecznie!)

Skopiuj obie wartości - będą potrzebne w konfiguracji.

## Konfiguracja

### 1. Ustawienie zmiennych środowiskowych

Utwórz plik `.env`:

```env
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
CALLBACK_URL=https://twoja-domena.com/oauth/github/callback
```

### 2. Rejestracja providera w aplikacji

Utwórz plik konfiguracyjny (np. `config/oauth.php`):

```php
<?php

use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Providers\GitHubProvider;
use NimblePHP\Authorization\Config;

function initializeOAuthProviders()
{
    $githubProvider = new GitHubProvider(
        $_ENV['GITHUB_CLIENT_ID'],
        $_ENV['GITHUB_CLIENT_SECRET']
    );
    
    Config::registerOAuthProvider('github', $githubProvider);
}

// Wykonaj w bootstrap aplikacji
initializeOAuthProviders();
```

Lub jeśli używasz konstruktora:

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Providers\GitHubProvider;
use NimblePHP\Authorization\Config;

// W bootstrap aplikacji
$githubProvider = new GitHubProvider(
    getenv('GITHUB_CLIENT_ID'),
    getenv('GITHUB_CLIENT_SECRET')
);

Config::registerOAuthProvider('github', $githubProvider);

$auth = new Authorization();
```

### 3. Ustaw URL callback'u

Callback URL musi być dokładnie taki sam jak w ustawieniach GitHub app:

```
https://twoja-domena.com/oauth/github/callback
```

## Implementacja logowania

### 1. Przycisk logowania

Utwórz link/przycisk w szablonie:

```html
<a href="/oauth/github/login" class="btn btn-github">
    Zaloguj się przez GitHub
</a>
```

### 2. Kontroler inicjalizacji logowania

Utwórz kontroler `/oauth/github/login`:

```php
<?php

namespace App\Controllers;

use NimblePHP\Authorization\Authorization;

class OAuthController
{
    public function gitHubLogin()
    {
        try {
            $auth = new Authorization();
            
            // URL callback'u - musi być taki sam jak w GitHub app
            $callbackUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/oauth/github/callback';
            
            // Uzyskaj URL autoryzacji GitHub
            $authUrl = $auth->initiateOAuthLogin('github', $callbackUrl);
            
            // Przekieruj użytkownika do GitHub
            header('Location: ' . $authUrl);
            exit;
            
        } catch (\Exception $e) {
            echo 'Błąd: ' . $e->getMessage();
            exit;
        }
    }
}
```

## Obsługa callback'u

### 1. Kontroler callback'u

Utwórz kontroler `/oauth/github/callback`:

```php
<?php

namespace App\Controllers;

use NimblePHP\Authorization\Authorization;

class OAuthController
{
    public function gitHubCallback()
    {
        $auth = new Authorization();
        
        try {
            // Pobierz kod z query string
            $code = $_GET['code'] ?? null;
            $error = $_GET['error'] ?? null;
            $errorDescription = $_GET['error_description'] ?? null;
            
            // Sprawdź błędy
            if ($error) {
                $msg = $errorDescription ? 
                    htmlspecialchars($errorDescription) : 
                    'Nieznany błąd podczas autoryzacji';
                throw new \Exception($msg);
            }
            
            if (!$code) {
                throw new \Exception('Brak kodu autoryzacyjnego. Spróbuj ponownie.');
            }
            
            // Obsłuż callback i pobierz dane użytkownika
            $userData = $auth->handleOAuthCallback($code, 'github');
            
            // Zaloguj użytkownika
            // Parametr createIfNotExists:
            // - true (domyślnie): tworzy nowe konto jeśli email nie istnieje
            // - false: loguje tylko istniejących użytkowników
            if ($auth->loginWithOAuth($userData, createIfNotExists: true)) {
                // Logowanie powiodło się
                header('Location: /dashboard');
                exit;
            }
            
        } catch (\Exception $e) {
            // Obsłuż błąd
            echo 'Błąd autoryzacji: ' . htmlspecialchars($e->getMessage());
            exit;
        }
    }
}
```

### 2. Dane otrzymane z GitHub

Po pomyślnej autoryzacji otrzymasz:

```php
[
    'oauth_id'       => '12345678',                              // GitHub user ID
    'oauth_provider' => 'github',                                // Dostawca
    'username'       => 'octocat',                               // GitHub login
    'email'          => 'octocat@github.com',                    // Email użytkownika
    'name'           => 'The Octocat',                           // Imię i nazwisko
    'avatar'         => 'https://avatars.githubusercontent.com/u/1?v=4',  // Avatar URL
    'profile_url'    => 'https://github.com/octocat',            // URL profilu GitHub
    'provider'       => 'github'                                 // Dostawca (powtórzony)
]
```

## Niestandardowe providery OAuth2

Aby obsługiwać inne providery OAuth2 (Google, Facebook, itp.), zaimplementuj interfejs `OAuthProvider`:

```php
<?php

namespace App\OAuth;

use NimblePHP\Authorization\Interfaces\OAuthProvider;

class GoogleProvider implements OAuthProvider
{
    private const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';
    private const USER_API_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';

    private string $clientId;
    private string $clientSecret;

    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    public function getAuthorizationUrl(string $redirectUri, array $scopes = []): string
    {
        if (empty($scopes)) {
            $scopes = ['openid', 'profile', 'email'];
        }

        return self::AUTHORIZE_URL . '?' . http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'access_type' => 'offline',
        ]);
    }

    public function exchangeCodeForToken(string $code, string $redirectUri): string
    {
        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'grant_type' => 'authorization_code',
        ];

        // Implementuj zapytanie HTTP POST
        $response = $this->makeRequest('POST', self::TOKEN_URL, $params);
        
        return $response['access_token'];
    }

    public function getUserData(string $accessToken): array
    {
        // Implementuj pobranie danych użytkownika
        $user = $this->makeAuthenticatedRequest(
            'GET', 
            self::USER_API_URL, 
            $accessToken
        );

        return [
            'oauth_id' => $user['id'],
            'oauth_provider' => 'google',
            'username' => $user['email'],
            'email' => $user['email'],
            'name' => $user['name'],
            'avatar' => $user['picture'],
            'profile_url' => 'https://myaccount.google.com/',
        ];
    }

    public function getName(): string
    {
        return 'google';
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    private function makeRequest(string $method, string $url, array $data = []): array
    {
        // Implementuj HTTP client (curl, Guzzle, itp.)
    }

    private function makeAuthenticatedRequest(
        string $method, 
        string $url, 
        string $accessToken
    ): array {
        // Implementuj HTTP client z headerem Authorization
    }
}
```

Następnie zarejestruj providera:

```php
$googleProvider = new \App\OAuth\GoogleProvider(
    $_ENV['GOOGLE_CLIENT_ID'],
    $_ENV['GOOGLE_CLIENT_SECRET']
);

Config::registerOAuthProvider('google', $googleProvider);
```

## Bezpieczeństwo

### 1. State Parameter

GitHub provider automatycznie generuje i waliduje parametr `state` dla ochrony przed atakami CSRF.

### 2. HTTPS

Zawsze używaj HTTPS w produkcji:
- URL callback'u w GitHub app musi być HTTPS
- Transfery token'ów powinny być szyfrowane

### 3. Client Secret

- Nigdy nie udostępniaj `Client Secret` publicznie
- Przechowuj w zmiennych środowiskowych
- Nie commituj do Git'a

### 2. Account Linking

OAuth obsługuje łączenie kont poprzez matching e-maila:
- Jeśli użytkownik z tym e-mailem już istnieje, jego konto jest aktualizowane
- Zapewnia bezpieczeństwo przed duplikowaniem kont

### 3. Rate Limiting

Rate limiting biblioteki chroni przed atakami brute-force:

```php
if ($auth->isLoginRateLimited($identifier)) {
    echo 'Zbyt wiele prób logowania. Spróbuj za ' . 
         $auth->getLoginLockoutTimeRemaining($identifier) . 
         ' sekund.';
}
```

## Troubleshooting

### Błąd: "Brak kodu autoryzacyjnego"

**Przyczyny:**
- Użytkownik anulował autoryzację
- GitHub app nie jest poprawnie skonfigurowana
- Authorization callback URL nie zgadza się

**Rozwiązanie:**
```php
// Wyświetl parametry URL
echo "Code: " . ($_GET['code'] ?? 'NULL');
echo "Error: " . ($_GET['error'] ?? 'NULL');
echo "Error desc: " . ($_GET['error_description'] ?? 'NULL');
```

### Błąd: "GitHub API error: Bad credentials"

**Przyczyny:**
- Zły Client ID lub Client Secret
- Token jest wygaszony

**Rozwiązanie:**
- Sprawdź poświadczenia w `https://github.com/settings/developers`
- Zregeneruj Client Secret jeśli podejrzeń

### Błąd: "redirect_uri_mismatch"

**Przyczyna:**
- URL callback'u w żądaniu nie zgadza się z URL'em w GitHub app

**Rozwiązanie:**
```php
// Callback URL musi być dokładnie taki sam
$callbackUrl = 'https://twoja-domena.com/oauth/github/callback';
$auth->initiateOAuthLogin('github', $callbackUrl);
```

### Błąd: "Invalid request: Callback URL mismatch"

**Przyczyna:**
- Callback URL w GitHub app jest nieprawidłowy

**Rozwiązanie:**
1. Przejdź do https://github.com/settings/developers
2. Wybierz aplikację
3. Zaktualizuj "Authorization callback URL"
4. Zapisz zmiany
5. Spróbuj ponownie

### Logowanie działa, ale e-mail użytkownika nie jest pobierany

**Przyczyna:**
- GitHub app nie ma uprawnień do odczytu e-maila

**Rozwiązanie:**
- Przegląd uprawnień w GitHub app settings
- Sprawdź, czy użytkownik udostępnił e-mail

```php
// GitHubProvider automatycznie próbuje pobierać e-mail z API
// Jeśli private, pobiera z listy adresów e-mail
```

### Sesja wygasa między initiateOAuthLogin a handleOAuthCallback

**Przyczyna:**
- Sesja jest zbyt krótka
- Serwer resetuje sesje

**Rozwiązanie:**
```php
// W handleOAuthCallback sprawdź czy sesja istnieje
$redirectUri = $this->session->get('oauth_redirect_uri');
if (!$redirectUri) {
    // Sesja wygasła - może być konieczne ponowne autoryzowanie
}
```

## Przykład pełnej implementacji

```php
<?php

namespace App\Controllers;

use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\GitHubProvider;

class AuthController
{
    private Authorization $auth;

    public function __construct()
    {
        $this->auth = new Authorization();
        
        // Rejestracja GitHub provider
        $github = new GitHubProvider(
            $_ENV['GITHUB_CLIENT_ID'],
            $_ENV['GITHUB_CLIENT_SECRET']
        );
        Config::registerOAuthProvider('github', $github);
    }

    public function loginForm()
    {
        // Wyświetl formularz logowania
        echo '<a href="/auth/oauth/github">Zaloguj się przez GitHub</a>';
    }

    public function oauthGitHub()
    {
        try {
            $callbackUrl = $this->getCallbackUrl();
            $authUrl = $this->auth->initiateOAuthLogin('github', $callbackUrl);
            
            header('Location: ' . $authUrl);
            exit;
        } catch (\Exception $e) {
            http_response_code(400);
            echo 'Błąd: ' . $e->getMessage();
        }
    }

    public function oauthCallback()
    {
        try {
            $code = $_GET['code'] ?? null;
            $error = $_GET['error'] ?? null;

            if ($error) {
                throw new \Exception($_GET['error_description'] ?? 'Nieznany błąd');
            }

            if (!$code) {
                throw new \Exception('Brak kodu autoryzacyjnego');
            }

            $userData = $this->auth->handleOAuthCallback($code, 'github');
            $this->auth->loginWithOAuth($userData);

            header('Location: /dashboard');
            exit;

        } catch (\Exception $e) {
            http_response_code(401);
            echo 'Błąd logowania: ' . $e->getMessage();
        }
    }

    private function getCallbackUrl(): string
    {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        return $protocol . '://' . $host . '/auth/oauth/callback';
    }
}
```

## Dodatkowe zasoby

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [NimblePHP Authorization Docs](https://github.com/nimblephp/authorization)
