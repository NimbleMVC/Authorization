# NimblePHP Authorization

Kompletna biblioteka autoryzacyjna dla frameworka NimblePHP z funkcjonalnościami:
- Bezpieczne zarządzanie użytkownikami i hasłami
- System Role-Based Access Control (RBAC)
- Ochrona przed atakami brute-force (Rate Limiting)
- Elastyczne, niestandardowe hasherowanie haseł
- Automatyczne aktualizowanie skrótów haseł
- Dwuetapowa weryfikacja (2FA) - TOTP i Email
- OAuth2 - Logowanie społeczne (GitHub)
- JWT - Bezstanowe tokeny dla API
- API Keys - Stacjonarne klucze dla dostępu programistycznego

## Konfiguracja

Biblioteka obsługuje podstawową konfigurację poprzez zmienne środowiskowe.

### Zmienne środowiskowe

```env
# Typ autoryzacji: 'username' lub 'email'
AUTHORIZATION_TYPE=username

# Nazwa tabeli użytkowników
AUTHORIZATION_TABLE=accounts

# Wymaganie aktywacji konta przed logowaniem (true/false)
AUTHORIZATION_REQUIRE_ACTIVATION=false

# Domyślna polityka autoryzacji - czy autoryzacja jest wymagana dla wszystkich kontrolerów (true/false)
AUTHORIZATION_REQUIRE_AUTH_BY_DEFAULT=false

# Konfiguracja kolumn
AUTHORIZATION_COLUMN_ID=id
AUTHORIZATION_COLUMN_USERNAME=username
AUTHORIZATION_COLUMN_EMAIL=email
AUTHORIZATION_COLUMN_PASSWORD=password
AUTHORIZATION_COLUMN_ACTIVE=active

# Konfiguracja Rate Limiting (ochrona przed atakami brute-force)
AUTHORIZATION_RATE_LIMIT_ENABLED=true
AUTHORIZATION_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHORIZATION_RATE_LIMIT_LOCKOUT_DURATION=900
```

### Konfiguracja PHP

```php
use NimblePHP\Authorization\Config;

// Ustawienia typu autoryzacji
Config::$authType = 'email'; // lub 'username'

// Wymaganie aktywacji konta
Config::$requireActivation = true; // lub false

// Domyślna polityka autoryzacji
Config::$requireAuthByDefault = true; // lub false

// Konfiguracja kolumn
Config::$columns = [
    'id' => 'user_id',
    'username' => 'login',
    'email' => 'email_address',
    'password' => 'hashed_password',
    'active' => 'is_active'
];
```

## Instalacja

```bash
composer require nimblephp/authorization
```

## Bezpieczeństwo

### Rate Limiting (Ochrona przed atakami brute-force)

Biblioteka zawiera wbudowaną ochronę przed atakami brute-force na logowanie. System Rate Limiting śledzi nieudane próby logowania i tymczasowo blokuje konto.

#### Konfiguracja Rate Limiting

```php
use NimblePHP\Authorization\Config;

// Włączenie/wyłączenie rate limitingu (domyślnie: true)
Config::$rateLimitEnabled = true;

// Maksymalna liczba nieudanych prób (domyślnie: 5)
Config::$rateLimitMaxAttempts = 5;

// Czas blokady w sekundach (domyślnie: 900 = 15 minut)
Config::$rateLimitLockoutDuration = 900;
```

#### Obsługiwanie excepcji Rate Limiting

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\RateLimitExceededException;

$auth = new Authorization();

try {
    $loggedIn = $auth->login('user@example.com', 'password123');
    if ($loggedIn) {
        echo "Zalogowano pomyślnie!";
    } else {
        echo "Nieprawidłowe dane logowania!";
    }
} catch (RateLimitExceededException $e) {
    echo "Konto tymczasowo zablokowane z powodu zbyt wielu nieudanych prób logowania.";
    echo "Spróbuj ponownie za " . $e->getRemainingLockoutTime() . " sekund.";
    // Zwróć HTTP 429 (Too Many Requests)
    http_response_code(429);
}
```

### Niestandardowe hashowanie haseł

Biblioteka pozwala na implementację własnego systemu hashowania haseł poprzez interfejs `PasswordHasher`. Domyślnie używa bezpiecznego systemu VersionedHasher, ale możesz łatwo zastąpić go swoją implementacją.

#### Dostępne implementacje

Biblioteka zawiera kilka gotowych implementacji:

1. **DefaultPasswordHasher** - Domyślna implementacja używająca VersionedHasher (rekomendowana)
   - Automatycznie aktualizuje skróty haseł przy logowaniu
   - Obsługuje wiele wersji algorytmów hashowania

2. **BcryptPasswordHasher** - Użycie PHP's native password_hash z algorytmem bcrypt
   - Bezpieczne, ale wolniejsze
   - Koszt: 12 (customizable)

3. **ArgonPasswordHasher** - Użycie PHP's password_hash z algorytmem Argon2id
   - Najbardziej bezpieczne, oporne na ataki GPU
   - Pamięć: 65536 MB, Iteracje: 4

4. **CustomHasherExample** - Szablon do implementacji własnego hashera

#### Implementacja niestandardowego hashera

Utwórz klasę implementującą interfejs `PasswordHasher`:

```php
use NimblePHP\Authorization\Interfaces\PasswordHasher;

class MyCustomHasher implements PasswordHasher
{
    /**
     * Hashuje hasło
     */
    public function hash(string $password): string
    {
        // Twoja implementacja hashowania
        return hash('sha256', $password . 'moja_sól');
    }

    /**
     * Weryfikuje hasło przeciwko skrótowi
     */
    public function verify(string $hash, string $password): bool
    {
        return hash_equals($hash, $this->hash($password));
    }

    /**
     * Sprawdza czy skrót wymaga rehash'u (dla algorytmów obsługujących aktualizację)
     */
    public function needsRehash(string $hash): bool
    {
        // Zwróć true jeśli hash wymaga aktualizacji
        return false;
    }
}
```

#### Konfiguracja niestandardowego hashera

```php
use NimblePHP\Authorization\Config;
use MyCustomHasher;

// Zarejestruj swój hasher
Config::setPasswordHasher(new MyCustomHasher());
```

Lub użyj jednej z gotowych implementacji:

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Hashers\BcryptPasswordHasher;
use NimblePHP\Authorization\Hashers\ArgonPasswordHasher;

// Użyj Bcrypt
Config::setPasswordHasher(new BcryptPasswordHasher());

// Lub Argon2id (najbezpieczniejszy)
Config::setPasswordHasher(new ArgonPasswordHasher());
```

#### Automatyczne aktualizowanie haseł

System domyślnie (z DefaultPasswordHasher) automatycznie aktualizuje hasła podczas logowania jeśli potrzebne. Umożliwia to bezproblemową migrację między algorytmami:

```php
// Jeśli zmienisz algorytm hasherowania, wszystkie hasła zostaną automatycznie
// zaktualizowane przy następnym logowaniu użytkownika
try {
    $loggedIn = $auth->login('user@example.com', 'password123');
    // Hasło zostało automatycznie rehash'owane jeśli było potrzebne
} catch (RateLimitExceededException $e) {
    // Obsłuż rate limit
}
```

### Dwuetapowa weryfikacja (2FA)

Biblioteka zawiera wbudowaną obsługę uwierzytelniania dwuetapowego (2FA/MFA). Obsługuje wiele metod weryfikacji:
- **TOTP** (Time-based One-Time Password) - zgodne z Google Authenticator i innymi aplikacjami
- **Email** - kody wysyłane na adres email użytkownika

#### Konfiguracja 2FA

Zarejestruj dostawców 2FA w Twojej aplikacji:

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\TOTPProvider;
use NimblePHP\Authorization\Providers\EmailProvider;

// Zarejestruj TOTP provider (Google Authenticator)
Config::registerTwoFactorProvider('totp', new TOTPProvider('Moja Aplikacja'));

// Zarejestruj Email provider
$emailProvider = new EmailProvider();
$emailProvider->setEmailCallback(function($email, $code) {
    // Wyślij kod na email użytkownika
    mail($email, 'Twój kod weryfikacyjny', "Kod: $code");
});
Config::registerTwoFactorProvider('email', $emailProvider);
```

#### TOTP (Google Authenticator)

TOTP jest najbardziej bezpieczną i popularną metodą 2FA. Generuje kody QR, które użytkownik skanuje swoją aplikacją authenticatora.

**Włączenie 2FA dla użytkownika:**

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();

// Sprawdź że użytkownik jest zalogowany
if ($auth->isAuthorized()) {
    // Pobierz TOTP provider
    $totp = Config::getTwoFactorProvider('totp');
    
    // Włącz 2FA i zwróć informacje o QR kodzie
    $result = $auth->enableTwoFactorAuth($totp);
    
    echo "Secret: " . $result['secret'];
    echo "QR Code URL: " . $result['qr_code'];
    echo "Provider: " . $result['provider'];
}
```

**Wyświetlanie QR kodu dla użytkownika:**

```php
// W szablonie HTML
<img src="<?php echo htmlspecialchars($qrCodeUrl); ?>" alt="2FA QR Code">
<p>Skanuj kod QR za pomocą aplikacji authenticatora (Google Authenticator, Authy, itp.)</p>
```

**Weryfikacja kodu TOTP podczas logowania:**

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\PendingTwoFactorException;
use NimblePHP\Authorization\Exceptions\TwoFactorException;

$auth = new Authorization();

try {
    // Logowanie z hasłem
    $loggedIn = $auth->login('user@example.com', 'password123');
    
    if ($loggedIn && !$auth->isTwoFactorEnabled($auth->getAuthorizedId())) {
        // 2FA nie jest włączone, zalogowanie ukończone
        echo "Zalogowano pomyślnie!";
    }
} catch (PendingTwoFactorException $e) {
    // Użytkownik ma 2FA - potrzebna weryfikacja
    $userId = $e->getUserId();
    $provider = $e->getProvider();
    
    // Przekieruj do strony weryfikacji 2FA
    // Przechowaj userId w sesji jeśli potrzebne
    echo "Proszę wpisać kod z Twojej aplikacji authenticatora";
} catch (RateLimitExceededException $e) {
    // Obsłuż rate limit
    echo "Zbyt wiele prób. Spróbuj za " . $e->getRemainingTime() . " sekund.";
}

// Na stronie weryfikacji 2FA:
try {
    $verified = $auth->verifyTwoFactorCode($_POST['2fa_code']);
    
    if ($verified) {
        echo "Zalogowano pomyślnie!";
    }
} catch (TwoFactorException $e) {
    echo "Nieprawidłowy kod: " . $e->getMessage();
}
```

#### Email 2FA

Email provider wysyła kody weryfikacyjne na adres email użytkownika.

**Konfiguracja:**

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\EmailProvider;

$emailProvider = new EmailProvider(6, 600); // 6-cyfrowy kod, ważny 10 minut

// Ustaw funkcję do wysyłania emaili
$emailProvider->setEmailCallback(function($email, $code) {
    // Użyj Twojego systemu wysyłania emaili
    sendEmail($email, 'Kod weryfikacyjny', "Twój kod: $code");
});

Config::registerTwoFactorProvider('email', $emailProvider);
```

**Wysłanie kodu weryfikacyjnego:**

```php
$emailProvider = Config::getTwoFactorProvider('email');

// Wyślij kod na email użytkownika
$code = $emailProvider->generateCode('user@example.com');
```

#### Wyłączenie 2FA

```php
if ($auth->isAuthorized()) {
    if ($auth->isTwoFactorEnabled()) {
        $auth->disableTwoFactorAuth();
        echo "2FA wyłączone";
    }
}
```

#### Kody odzyskania (Recovery Codes)

TOTP provider generuje kody odzyskania, które użytkownik może użyć jeśli utraci dostęp do swojego authenticatora:

```php
$totp = Config::getTwoFactorProvider('totp');
$secret = 'JBSWY3DPEBLW64TMMQ'; // Sekret użytkownika

// Generuj kody odzyskania
$recoveryCodes = $totp->getRecoveryCodes($secret, 10); // Generuj 10 kodów

// Wyświetl użytkownikowi - powinien je zapisać w bezpiecznym miejscu
foreach ($recoveryCodes as $code) {
    echo $code . "\n";
}

// Weryfikacja kodu odzyskania podczas logowania
if ($totp->verifyRecoveryCode($secret, $_POST['recovery_code'])) {
    // Kod jest ważny - zaloguj użytkownika
    $auth->verifyTwoFactorCode($_POST['recovery_code']);
}
```

## Funkcjonalności

### Atrybuty autoryzacji

Biblioteka oferuje elastyczny system kontroli dostępu za pomocą atrybutów PHP 8+.

#### Dostępne atrybuty

- `#[RequireAuth]` - wymaga autoryzacji dla danego kontrolera/metody
- `#[NoAuth]` - wyłącza autoryzację dla danego kontrolera/metody

#### Konfiguracja domyślnej polityki autoryzacji

Możesz skonfigurować domyślną politykę autoryzacji dla całej aplikacji:

```php
use NimblePHP\Authorization\Config;

// Domyślnie autoryzacja NIE jest wymagana (tradycyjne podejście)
Config::$requireAuthByDefault = false;

// Domyślnie autoryzacja JEST wymagana (bezpieczniejsze podejście)
Config::$requireAuthByDefault = true;
```

#### Przykłady użycia atrybutów

##### Opcja 1: Domyślnie autoryzacja NIE wymagana

```php
use NimblePHP\Authorization\Attributes\RequireAuth;
use NimblePHP\Authorization\Config;

// Konfiguracja
Config::$requireAuthByDefault = false;

class UserController
{
    // Metoda publiczna - nie wymaga autoryzacji
    public function publicInfo() {
        return "Informacje publiczne";
    }

    // Metoda chroniona - wymaga autoryzacji
    #[RequireAuth]
    public function profile() {
        return "Profil użytkownika";
    }

    // Metoda chroniona - wymaga autoryzacji
    #[RequireAuth]
    public function settings() {
        return "Ustawienia użytkownika";
    }
}
```

##### Opcja 2: Domyślnie autoryzacja WYMAGANA

```php
use NimblePHP\Authorization\Attributes\NoAuth;
use NimblePHP\Authorization\Config;

// Konfiguracja
Config::$requireAuthByDefault = true;

class UserController
{
    // Metoda publiczna - wyłączenie autoryzacji
    #[NoAuth]
    public function login() {
        return "Formularz logowania";
    }

    // Metoda publiczna - wyłączenie autoryzacji
    #[NoAuth]
    public function register() {
        return "Formularz rejestracji";
    }

    // Metoda chroniona - domyślnie wymaga autoryzacji
    public function profile() {
        return "Profil użytkownika";
    }

    // Metoda chroniona - domyślnie wymaga autoryzacji
    public function settings() {
        return "Ustawienia użytkownika";
    }
}
```

#### Middleware autoryzacji

Biblioteka dostarcza `AuthorizationMiddleware` który automatycznie sprawdza autoryzację na podstawie atrybutów i konfiguracji. Middleware należy zarejestrować w aplikacji NimblePHP.

**Logika działania middleware:**

1. **Jeśli jest atrybut `#[NoAuth]`** → autoryzacja NIE jest wymagana
2. **Jeśli jest atrybut `#[RequireAuth]`** → autoryzacja JEST wymagana
3. **Jeśli nie ma żadnego atrybutu** → sprawdza konfigurację `$requireAuthByDefault`

### Klasa Authorization

Główna klasa odpowiedzialna za zarządzanie sesjami użytkowników i proces autoryzacji.

#### Metody klasy Authorization

- `isAuthorized(): bool` - sprawdza czy użytkownik jest zalogowany
- `getAuthorizedId(): int` - zwraca ID zalogowanego użytkownika
- `getCurrentUser(): ?array` - zwraca dane aktualnie zalogowanego użytkownika
- `register(string $username, string $password): bool` - rejestruje nowego użytkownika
- `login(string $username, string $password): bool` - loguje użytkownika (z automatycznym rehash hasła jeśli potrzebne)
- `logout(): void` - wylogowuje użytkownika

### Klasa Account

Klasa odpowiedzialna za operacje bazodanowe na kontach użytkowników.

#### Metody klasy Account

- `getId(): ?int` - zwraca ID konta
- `setId(int $id): void` - ustawia ID konta
- `getTableInstance(): Table` - zwraca instancję tabeli bazy danych
- `getAccount(): ?array` - zwraca dane konta bieżącego użytkownika
- `find(array $conditions): ?array` - wyszukuje konto na podstawie warunków
- `insert(array $data): bool` - dodaje nowe konto do bazy danych
- `update(array $data): bool` - aktualizuje dane konta
- `usernameExists(string $username): bool` - sprawdza czy nazwa użytkownika już istnieje
- `emailExists(string $email): bool` - sprawdza czy email już istnieje
- `changePassword(string $password): bool` - zmienia hasło konta
- `isActive(?int $accountId = null): bool` - sprawdza czy konto jest aktywne
- `activate(?int $accountId = null): bool` - aktywuje konto
- `deactivate(?int $accountId = null): bool` - dezaktywuje konto

## Role-Based Access Control (RBAC)

Biblioteka oferuje kompletny system RBAC (Role-Based Access Control) umożliwiający precyzyjną kontrolę dostępu na podstawie ról i uprawnień.

### Konfiguracja RBAC

#### Tabele bazy danych

Przed rozpoczęciem korzystania z RBAC należy użyć komendy CLI uruchamiającą migracje modułów:
```shell
php vendor/bin/nimble project:update
```

#### Zmienne środowiskowe dla RBAC

```env
# Tabele RBAC
AUTHORIZATION_TABLE=accounts
AUTHORIZATION_ROLES_TABLE=account_roles
AUTHORIZATION_PERMISSIONS_TABLE=account_permissions
AUTHORIZATION_USER_ROLES_TABLE=account_user_roles
AUTHORIZATION_ROLE_PERMISSIONS_TABLE=account_role_permissions

# Kolumny tabeli ról
AUTHORIZATION_ROLE_COLUMN_ID=id
AUTHORIZATION_ROLE_COLUMN_NAME=name
AUTHORIZATION_ROLE_COLUMN_DESCRIPTION=description
AUTHORIZATION_ROLE_COLUMN_CREATED_AT=created_at

# Kolumny tabeli uprawnień
AUTHORIZATION_PERMISSION_COLUMN_ID=id
AUTHORIZATION_PERMISSION_COLUMN_NAME=name
AUTHORIZATION_PERMISSION_COLUMN_DESCRIPTION=description
AUTHORIZATION_PERMISSION_COLUMN_GROUP=group
AUTHORIZATION_PERMISSION_COLUMN_CREATED_AT=created_at

# Kolumny tabeli user_roles
AUTHORIZATION_USER_ROLE_COLUMN_ID=id
AUTHORIZATION_USER_ROLE_COLUMN_USER_ID=user_id
AUTHORIZATION_USER_ROLE_COLUMN_ROLE_ID=role_id
AUTHORIZATION_USER_ROLE_COLUMN_ASSIGNED_AT=assigned_at

# Kolumny tabeli role_permissions
AUTHORIZATION_ROLE_PERMISSION_COLUMN_ID=id
AUTHORIZATION_ROLE_PERMISSION_COLUMN_ROLE_ID=role_id
AUTHORIZATION_ROLE_PERMISSION_COLUMN_PERMISSION_ID=permission_id
AUTHORIZATION_ROLE_PERMISSION_COLUMN_ASSIGNED_AT=assigned_at
```

### Atrybuty RBAC

#### Dostępne atrybuty

**Podstawowe atrybuty:**
- `#[HasRole('admin')]` - sprawdza czy użytkownik ma określoną rolę
- `#[HasPermission('users.edit')]` - sprawdza czy użytkownik ma określone uprawnienie

**Zaawansowane atrybuty dla wielu sprawdzeń:**
- `#[HasAnyRole('admin', 'moderator')]` - sprawdza czy użytkownik ma którąkolwiek z wymienionych ról
- `#[HasAllRoles('admin', 'editor')]` - sprawdza czy użytkownik ma wszystkie wymienione role
- `#[HasAnyPermission('users.edit', 'users.delete')]` - sprawdza czy użytkownik ma którekolwiek z wymienionych uprawnień

#### Przykład użycia atrybutów RBAC

```php
use NimblePHP\Authorization\Attributes\HasRole;
use NimblePHP\Authorization\Attributes\HasPermission;
use NimblePHP\Authorization\Attributes\HasAnyRole;
use NimblePHP\Authorization\Attributes\HasAllRoles;
use NimblePHP\Authorization\Attributes\HasAnyPermission;

class AdminController
{
    // Podstawowe sprawdzenia
    #[HasRole('admin')]
    public function dashboard()
    {
        return "Panel administratora - tylko dla adminów";
    }

    #[HasPermission('users.edit')]
    public function editUser($userId)
    {
        return "Edycja użytkownika: " . $userId;
    }

    // Zaawansowane sprawdzenia wielu ról/uprawnień
    #[HasAnyRole('admin', 'moderator')]
    public function moderateContent()
    {
        return "Moderacja treści - dla adminów lub moderatorów";
    }

    #[HasAllRoles('admin', 'editor')]
    public function manageAllContent()
    {
        return "Zarządzanie całą treścią - tylko dla adminów którzy są też edytorami";
    }

    #[HasAnyPermission('content.edit', 'content.delete')]
    public function modifyContent($contentId)
    {
        return "Modyfikacja treści: " . $contentId;
    }

    // Wielokrotne atrybuty (każdy musi być spełniony)
    #[HasRole('admin')]
    #[HasPermission('system.settings')]
    public function systemSettings()
    {
        return "Ustawienia systemu - wymaga roli admin i uprawnienia system.settings";
    }
}
```

### Klasa Role

Zarządza rolami w systemie.

#### Metody klasy Role

- `create(string $name, ?string $description = null): bool` - tworzy nową rolę
- `findByName(string $name): ?array` - wyszukuje rolę po nazwie
- `assignToUser(int $userId): bool` - przypisuje rolę użytkownikowi
- `removeFromUser(int $userId): bool` - usuwa rolę od użytkownika
- `addPermission(int $permissionId): bool` - dodaje uprawnienie do roli
- `removePermission(int $permissionId): bool` - usuwa uprawnienie z roli
- `getPermissions(): array` - zwraca wszystkie uprawnienia roli
- `getUsersWithRole(): array` - zwraca wszystkich użytkowników z daną rolą

### Klasa Permission

Zarządza uprawnieniami w systemie.

#### Metody klasy Permission

- `create(string $name, ?string $description = null, ?string $group = null): bool` - tworzy nowe uprawnienie
- `findByName(string $name): ?array` - wyszukuje uprawnienie po nazwie
- `assignToRole(int $roleId): bool` - przypisuje uprawnienie do roli
- `getRolesWithPermission(): array` - zwraca wszystkie role mające dane uprawnienie
- `getPermissionGroups(): array` - zwraca wszystkie grupy uprawnień

### Rozszerzone metody klasy Authorization

#### Metody sprawdzania ról i uprawnień

- `hasRole(string $roleName): bool` - sprawdza czy użytkownik ma rolę
- `hasPermission(string $permissionName): bool` - sprawdza czy użytkownik ma uprawnienie
- `hasAnyRole(array $roleNames): bool` - sprawdza czy użytkownik ma którąkolwiek z ról
- `hasAllRoles(array $roleNames): bool` - sprawdza czy użytkownik ma wszystkie role
- `hasAnyPermission(array $permissionNames): bool` - sprawdza czy użytkownik ma którekolwiek uprawnienie
- `hasAllPermissions(array $permissionNames): bool` - sprawdza czy użytkownik ma wszystkie uprawnienia

#### Metody zarządzania rolami

- `getUserRoles(): array` - zwraca wszystkie role użytkownika
- `getUserPermissions(): array` - zwraca wszystkie uprawnienia użytkownika
- `assignRole(string $roleName): bool` - przypisuje rolę użytkownikowi
- `removeRole(string $roleName): bool` - usuwa rolę od użytkownika

### Rozszerzone metody klasy Account

#### Metody zarządzania rolami konta

- `assignRole(string $roleName, ?int $accountId = null): bool` - przypisuje rolę do konta
- `removeRole(string $roleName, ?int $accountId = null): bool` - usuwa rolę z konta
- `hasRole(string $roleName, ?int $accountId = null): bool` - sprawdza czy konto ma rolę
- `hasPermission(string $permissionName, ?int $accountId = null): bool` - sprawdza czy konto ma uprawnienie
- `getRoles(?int $accountId = null): array` - zwraca wszystkie role konta
- `getPermissions(?int $accountId = null): array` - zwraca wszystkie uprawnienia konta
- `setRoles(array $roleNames, ?int $accountId = null): bool` - ustawia role dla konta (zastępuje istniejące)
- `clearRoles(?int $accountId = null): bool` - usuwa wszystkie role z konta

## Przykład użycia

### Podstawowa konfiguracja

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();
```

### Rejestracja użytkownika

#### Autoryzacja przez username

```php
use NimblePHP\Authorization\Config;

// Konfiguracja dla username
Config::$authType = 'username';

try {
    $success = $auth->register('jan_kowalski', 'bezpieczne_haslo123');
    if ($success) {
        echo "Użytkownik został pomyślnie zarejestrowany!";
    }
} catch (InvalidArgumentException $e) {
    echo "Błąd rejestracji: " . $e->getMessage();
}
```

#### Autoryzacja przez email

```php
use NimblePHP\Authorization\Config;

// Konfiguracja dla email
Config::$authType = 'email';

try {
    $success = $auth->register('jan_kowalski', 'bezpieczne_haslo123', 'jan@example.com');
    if ($success) {
        echo "Użytkownik został pomyślnie zarejestrowany!";
    }
} catch (InvalidArgumentException $e) {
    echo "Błąd rejestracji: " . $e->getMessage();
}
```

### Logowanie użytkownika

#### Logowanie przez username lub email

Metoda `login()` automatycznie rozpoznaje typ autoryzacji na podstawie konfiguracji:

```php
try {
    // Dla username autoryzacji
    if (Config::$authType === 'username') {
        $loggedIn = $auth->login('jan_kowalski', 'bezpieczne_haslo123');
    }
    // Dla email autoryzacji
    else {
        $loggedIn = $auth->login('jan@example.com', 'bezpieczne_haslo123');
    }

    if ($loggedIn) {
        echo "Zalogowano pomyślnie!";
    } else {
        echo "Nieprawidłowe dane logowania!";
    }
} catch (InvalidArgumentException $e) {
    echo "Błąd logowania: " . $e->getMessage();
}
```

#### HTTP Basic Authentication

Biblioteka wspiera HTTP Basic Auth (RFC 7617) dla API i dostępu programistycznego:

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();

try {
    if ($auth->authenticateHttpBasic()) {
        echo "Autoryzacja HTTP Basic się powiodła";
        $userId = $auth->getAuthorizedId();
    }
} catch (InvalidArgumentException $e) {
    echo "Błąd formatu Authorization nagłówka: " . $e->getMessage();
    http_response_code(400);
} catch (RateLimitExceededException $e) {
    echo "Zbyt wiele prób logowania";
    http_response_code(429);
}
```

**Wysyłanie HTTP Basic Auth (z przeglądarki/curl):**

```bash
curl -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
     https://example.com/api/protected
```

**W JavaScript/Fetch API:**

```javascript
const username = 'user@example.com';
const password = 'bezpieczne_haslo123';
const credentials = btoa(username + ':' + password);

fetch('/api/protected', {
    headers: {
        'Authorization': 'Basic ' + credentials
    }
})
.then(response => response.json())
.then(data => console.log(data));
```

### Sprawdzanie statusu autoryzacji

```php
if ($auth->isAuthorized()) {
    $userId = $auth->getAuthorizedId();
    $userData = $auth->getCurrentUser();
    echo "Witaj, użytkownik o ID: " . $userId;
} else {
    echo "Użytkownik nie jest zalogowany.";
}
```

### Wylogowanie

```php
$auth->logout();
echo "Użytkownik został wylogowany.";
```

### Operacje na koncie

```php
use NimblePHP\Authorization\Account;

$account = new Account();
$userData = $account->getAccount();

if ($account->usernameExists('jan_kowalski')) {
    echo "Ta nazwa użytkownika jest już zajęta.";
}
```

### Konfigurowalne nazwy kolumn

Biblioteka pozwala na dostosowanie nazw kolumn w bazie danych:

```php
use NimblePHP\Authorization\Config;

// Dostosowanie nazw kolumn
Config::$columns = [
    'id' => 'user_id',
    'username' => 'login_name',
    'email' => 'user_email',
    'password' => 'password_hash',
    'created_at' => 'registration_date',
    'status' => 'user_status'
];

// Ustawienie niestandardowej nazwy tabeli
Config::$tableName = 'users';

// Ustawienie niestandardowego klucza sesji
Config::$sessionKey = 'user_session_id';

// Teraz wszystkie operacje będą używać nowych nazw
$userData = $auth->getCurrentUser();

// Ustawienie niestandardowej nazwy tabeli użytkowników
Config::$tableName = 'my_custom_accounts';

// Ustawienie niestandardowych nazw tabel RBAC
Config::$rolesTableName = 'my_roles';
Config::$permissionsTableName = 'my_permissions';
Config::$userRolesTableName = 'my_user_roles';
Config::$rolePermissionsTableName = 'my_role_permissions';
```

### Zarządzanie kontem

```php
use NimblePHP\Authorization\Account;

// Utworzenie instancji konta dla zalogowanego użytkownika
$account = new Account();

// Zmiana hasła
$account->changePassword('nowe_bezpieczne_haslo');

// Aktualizacja danych konta
$account->update([
    'email' => 'nowy@email.com',
    'updated_at' => date('Y-m-d H:i:s')
]);

// Pobranie ID konta
$userId = $account->getId();

// Ustawienie konkretnego ID konta
$account->setId(123);
```

### Aktywacja kont

Biblioteka obsługuje opcjonalną aktywację kont użytkowników. Gdy aktywacja jest włączona, nowo zarejestrowani użytkownicy nie mogą się zalogować dopóki ich konta nie zostaną aktywowane.

#### Konfiguracja aktywacji

```php
use NimblePHP\Authorization\Config;

// Włączenie wymagania aktywacji
Config::$requireActivation = true;

// Sprawdzenie czy aktywacja jest wymagana
if (Config::isActivationRequired()) {
    echo "Aktywacja kont jest wymagana";
}
```

#### Rejestracja z aktywacją

Gdy aktywacja jest włączona, nowo utworzone konta mają status `active = 0`:

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;

// Włączenie aktywacji
Config::$requireActivation = true;

$auth = new Authorization();

// Rejestracja użytkownika - konto będzie nieaktywne
$success = $auth->register('jan_kowalski', 'bezpieczne_haslo123', 'jan@example.com');

if ($success) {
    echo "Użytkownik zarejestrowany. Wymagana aktywacja konta.";
}

// Próba logowania przed aktywacją zakończy się niepowodzeniem
$loginResult = $auth->login('jan_kowalski', 'bezpieczne_haslo123');
// $loginResult będzie false
```

#### Zarządzanie aktywacją kont

```php
use NimblePHP\Authorization\Account;

$account = new Account();

// Sprawdzenie czy konto jest aktywne
$userId = 123;
if ($account->isActive($userId)) {
    echo "Konto jest aktywne";
} else {
    echo "Konto wymaga aktywacji";
}

// Aktywacja konta
$account->setId($userId);
$success = $account->activate();
if ($success) {
    echo "Konto zostało aktywowane";
}

// Dezaktywacja konta
$success = $account->deactivate($userId);
if ($success) {
    echo "Konto zostało dezaktywowane";
}

// Aktywacja bez ustawiania ID (używa bieżącego zalogowanego użytkownika)
$account->activate();
```

#### Logowanie z aktywacją

Gdy aktywacja jest włączona, tylko aktywne konta mogą się zalogować:

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;

Config::$requireActivation = true;

$auth = new Authorization();

// Logowanie nieaktywnego konta zakończy się niepowodzeniem
$loginResult = $auth->login('jan_kowalski', 'bezpieczne_haslo123');
if (!$loginResult) {
    echo "Logowanie nieudane. Sprawdź czy konto jest aktywowane.";
}
```

#### Wyłączenie aktywacji

Gdy aktywacja jest wyłączona, wszystkie konta są automatycznie traktowane jako aktywne:

```php
use NimblePHP\Authorization\Config;

// Wyłączenie aktywacji (domyślnie)
Config::$requireActivation = false;

// Wszystkie nowe konta będą miały active = 1
// Metoda isActive() zawsze zwróci true
```

### Praca z RBAC

#### Tworzenie ról i uprawnień

```php
use NimblePHP\Authorization\Role;
use NimblePHP\Authorization\Permission;

// Tworzenie roli administratora
$role = new Role();
$role->create('admin', 'Administrator systemu');

// Tworzenie uprawnień
$permission = new Permission();
$permission->create('users.manage', 'Zarządzanie użytkownikami', 'users');
$permission->create('content.publish', 'Publikacja treści', 'content');
$permission->create('system.settings', 'Ustawienia systemu', 'system');
```

#### Przypisywanie uprawnień do ról

```php
use NimblePHP\Authorization\Role;

// Znajdź rolę administratora
$role = new Role();
$roleData = $role->findByName('admin');
$role->setId($roleData['roles']['id']);

// Dodaj uprawnienia do roli
$role->addPermission(1); // users.manage
$role->addPermission(2); // content.publish
$role->addPermission(3); // system.settings
```

#### Zarządzanie użytkownikami i rolami

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Account;

$auth = new Authorization();
$account = new Account();

// Po zalogowaniu administratora
$userId = $auth->getAuthorizedId();

// Przypisz rolę administratora użytkownikowi
$account->setId($userId);
$account->assignRole('admin');

// Sprawdź czy użytkownik ma rolę
if ($auth->hasRole('admin')) {
    echo "Użytkownik jest administratorem";
}

// Sprawdź czy użytkownik ma uprawnienie
if ($auth->hasPermission('users.manage')) {
    echo "Użytkownik może zarządzać użytkownikami";
}
```

#### Zaawansowane sprawdzenia dostępu

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();

// Sprawdź czy użytkownik ma którąkolwiek z ról
if ($auth->hasAnyRole(['admin', 'moderator'])) {
    echo "Użytkownik ma uprawnienia moderatora lub wyższe";
}

// Sprawdź czy użytkownik ma wszystkie wymienione role
if ($auth->hasAllRoles(['admin', 'editor'])) {
    echo "Użytkownik jest adminem i edytorem";
}

// Sprawdź czy użytkownik ma którekolwiek z uprawnień
if ($auth->hasAnyPermission(['content.edit', 'content.delete'])) {
    echo "Użytkownik może edytować lub usuwać treści";
}

// Bardziej złożone warunki
$roles = ['admin', 'moderator', 'editor'];
$permissions = ['users.view', 'users.edit'];

// Sprawdź czy użytkownik ma którąkolwiek rolę LUB którekolwiek uprawnienie
if ($auth->hasAnyRole($roles) || $auth->hasAnyPermission($permissions)) {
    echo "Użytkownik ma odpowiednie uprawnienia";
}

// Sprawdź czy użytkownik ma którąkolwiek rolę ORAZ którekolwiek uprawnienie
if ($auth->hasAnyRole($roles) && $auth->hasAnyPermission($permissions)) {
    echo "Użytkownik ma rolę i uprawnienia";
}
```

#### Pobieranie ról i uprawnień użytkownika

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();

// Pobierz wszystkie role użytkownika
$userRoles = $auth->getUserRoles();
foreach ($userRoles as $role) {
    echo "Rola: " . $role['roles']['name'] . "\n";
}

// Pobierz wszystkie uprawnienia użytkownika
$userPermissions = $auth->getUserPermissions();
foreach ($userPermissions as $permission) {
    echo "Uprawnienie: " . $permission['permissions']['name'] . "\n";
}
```

#### Użycie atrybutów w kontrolerach

```php
use NimblePHP\Authorization\Attributes\HasRole;
use NimblePHP\Authorization\Attributes\HasPermission;

class AdminController
{
    #[HasRole('admin')]
    public function adminDashboard()
    {
        return "Panel administratora - tylko dla adminów";
    }

    #[HasRole('moderator')]
    public function moderateUsers()
    {
        return "Moderacja użytkowników";
    }

    #[HasPermission('users.edit')]
    public function editUser($userId)
    {
        return "Edycja użytkownika {$userId}";
    }

    #[HasPermission('content.delete')]
    public function deleteContent($contentId)
    {
        return "Usunięcie treści {$contentId}";
    }
}
```

#### Zarządzanie rolami przez API/admin panel

```php
use NimblePHP\Authorization\Role;
use NimblePHP\Authorization\Account;

// Tworzenie nowej roli
$role = new Role();
$role->create('editor', 'Edytor treści');

// Przypisywanie roli do użytkownika
$account = new Account($userId);
$account->assignRole('editor');

// Usuwanie roli od użytkownika
$account->removeRole('editor');

// Pobieranie wszystkich użytkowników z rolą
$role = new Role();
$roleData = $role->findByName('editor');
$role->setId($roleData['roles']['id']);
$usersWithRole = $role->getUsersWithRole();
```

## Walidacja danych

Biblioteka zawiera wbudowaną walidację:

- **Nazwa użytkownika**: nie może być pusta
- **Hasło**: minimum 6 znaków
- **Unikalność**: nazwa użytkownika musi być unikalna w systemie

## Bezpieczeństwo

- Hasła są hashowane przy użyciu biblioteki `VersionedHasher`
- Automatyczne rehash hasła podczas logowania jeśli algorytm się zmienił
- Wszystkie dane wejściowe są walidowane
- Sesje są zarządzane przez framework NimblePHP
- Chroni przed SQL injection poprzez używanie przygotowanych zapytań

## Struktura tabeli bazy danych

Biblioteka oczekuje tabel z następującymi kolumnami:

**Główna tabela użytkowników:**
```sql
CREATE TABLE accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255) NOT NULL,
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**Uwaga**: Kolumna `active` jest wymagana jeśli chcesz używać funkcji aktywacji kont. Jeśli nie planujesz używać tej funkcji, kolumna może być pominięta lub zawsze ustawiona na `1`.

Możesz dostosować nazwy kolumn poprzez konfigurację:

```php
use NimblePHP\Authorization\Config;

Config::$columns = [
    'id' => 'user_id',
    'username' => 'login_name',
    'email' => 'user_email',
    'password' => 'password_hash',
    'active' => 'is_active'
];
```

## Wyjątki

Biblioteka może rzucać następujące wyjątki:

- `InvalidArgumentException` - przy nieprawidłowych danych wejściowych
- `UnauthorizedException` - gdy użytkownik próbuje uzyskać dostęp do chronionego zasobu bez autoryzacji
- `RateLimitExceededException` - gdy limit nieudanych prób logowania został przekroczony (HTTP 429)
- `TwoFactorException` - gdy weryfikacja kodu 2FA nie powiodła się (kod nieprawidłowy lub wygasły)
- `PendingTwoFactorException` - gdy użytkownik zalogował się, ale wymaga weryfikacji 2FA (zawiera ID użytkownika i dostawcę)

## OAuth2 - Logowanie społeczne

Biblioteka wspiera logowanie za pośrednictwem OAuth2. Dostarczone są implementacje dla GitHub i przygotowana architektura do łatwego dodawania dodatkowych dostawców (Google, Facebook, itp.).

### Konfiguracja GitHub OAuth2

#### 1. Rejestracja aplikacji na GitHub

1. Przejdź na https://github.com/settings/developers
2. Kliknij "New OAuth App"
3. Wypełnij formularz:
   - **Application name**: Nazwa aplikacji
   - **Homepage URL**: https://twoja-domena.com
   - **Authorization callback URL**: https://twoja-domena.com/oauth/github/callback
4. Skopiuj Client ID i Client Secret

#### 2. Konfiguracja w aplikacji

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Providers\GitHubProvider;

$auth = new Authorization();

// Rejestracja providera
$githubProvider = new GitHubProvider(
    'YOUR_CLIENT_ID',
    'YOUR_CLIENT_SECRET'
);

\NimblePHP\Authorization\Config::registerOAuthProvider('github', $githubProvider);
```

#### 3. Inicjalizacja logowania OAuth

```php
// W kontrolerze - przekieruj użytkownika do GitHub
$auth = new Authorization();
$redirectUri = 'https://twoja-domena.com/oauth/github/callback';
$authUrl = $auth->initiateOAuthLogin('github', $redirectUri);

header('Location: ' . $authUrl);
```

#### 4. Obsługa callback'u

```php
// W kontrolerze callback'u (np. /oauth/github/callback)
$auth = new Authorization();

try {
    $code = $_GET['code'] ?? null;
    
    if (!$code) {
        throw new \Exception('Brak kodu autoryzacyjnego');
    }
    
    // Obsługa callbacku i pobieranie danych użytkownika
    $redirectUri = 'https://twoja-domena.com/oauth/github/callback';
    $userData = $auth->handleOAuthCallback($code, 'github');
    
    // Logowanie użytkownika (tworzy konto jeśli nie istnieje)
    if ($auth->loginWithOAuth($userData)) {
        header('Location: /dashboard');
        exit;
    }
} catch (\Exception $e) {
    echo 'Błąd autoryzacji: ' . $e->getMessage();
}
```

### Dane otrzymane z OAuth2

Po pomyślnej autoryzacji otrzymujesz takie dane:

**Dla GitHub OAuth2:**
```php
[
    'oauth_id' => '12345678',        // GitHub user ID
    'oauth_provider' => 'github',     // Dostawca OAuth
    'username' => 'octocat',          // GitHub login
    'email' => 'octocat@github.com',  // Email użytkownika
    'name' => 'The Octocat',          // Imię i nazwisko
    'avatar' => 'https://...',        // Avatar URL
    'profile_url' => 'https://...'    // URL profilu GitHub
]
```

### Tworzenie niestandardowego providera OAuth2

Aby dodać nowego dostawcę OAuth2, stwórz klasę implementującą `OAuthProvider`:

```php
<?php

namespace MyApp\OAuth;

use NimblePHP\Authorization\Interfaces\OAuthProvider;

class GoogleProvider implements OAuthProvider
{
    private string $clientId;
    private string $clientSecret;
    
    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }
    
    public function getAuthorizationUrl(string $state): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => 'https://twoja-domena.com/oauth/google/callback',
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state,
        ]);
    }
    
    public function exchangeCodeForToken(string $code): array
    {
        // Implementacja wymiany kodu na token
    }
    
    public function getUserData(string $accessToken): array
    {
        // Implementacja pobierania danych użytkownika
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
}
```

Następnie zarejestruj providera:

```php
$googleProvider = new \MyApp\OAuth\GoogleProvider('CLIENT_ID', 'CLIENT_SECRET');
\NimblePHP\Authorization\Config::registerOAuthProvider('google', $googleProvider);
```

### Bezpieczeństwo OAuth2

- Stan jest generowany losowo i walidowany podczas callbacku (ochrona przed CSRF)
- Dane OAuth są przechowywane w kolumnach `account_oauth_id` i `account_oauth_provider`
- Logowanie OAuth obsługuje matching e-maila - jeśli użytkownik z tym e-mailem już istnieje, jego konto jest połączone
- Można wymusić tworzenie nowych kont poprzez parametr `createIfNotExists`

```php
// Logowanie bez tworzenia konta jeśli użytkownik nie istnieje
$auth->loginWithOAuth($userData, createIfNotExists: false);
```

## Token-Based Authentication

Biblioteka wspiera nowoczesne metody autoryzacji API oparte na tokenach.

### JWT (JSON Web Tokens)

RFC 7519 standard dla stateless, bezpiecznych tokenów.

#### Konfiguracja

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\JWTProvider;

$jwtProvider = new JWTProvider(
    $_ENV['JWT_SECRET'],  // Minimum 32 characters
    'HS256',              // Algorithm
    3600                  // Default expiration (1 hour)
);

Config::registerTokenProvider('jwt', $jwtProvider);
```

#### Generowanie tokenu

```php
$auth = new Authorization();

if ($auth->login($username, $password)) {
    $token = $auth->generateToken(
        $auth->getAuthorizedId(),
        'jwt',
        ['role' => 'user'],
        3600
    );
    
    echo json_encode(['token' => $token]);
}
```

#### Walidacja tokenu

```php
$auth = new Authorization();

try {
    $tokenData = $auth->validateToken($authToken, 'jwt');
    $userId = $tokenData['user_id'];
    
    // Token jest ważny
    
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token']);
}
```

### API Keys

Stacjonarne klucze API z loggingiem i rate limitingiem.

#### Konfiguracja

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\APIKeyProvider;

$apiKeyProvider = new APIKeyProvider();

Config::registerTokenProvider('api_key', $apiKeyProvider);
```

#### Generowanie klucza

```php
$auth = new Authorization();

$apiKey = $auth->generateToken(
    $auth->getAuthorizedId(),
    'api_key',
    [
        'name' => 'My API Key',
        'scopes' => ['read:users', 'write:posts'],
        'rate_limit' => 1000  // Requests per hour
    ],
    365 * 24 * 3600  // 1 year
);

echo $apiKey;  // sk_abcdef1234567890...
```

#### Walidacja klucza

```php
$auth = new Authorization();

try {
    $keyData = $auth->validateToken($apiKey, 'api_key');
    $userId = $keyData['user_id'];
    $scopes = $keyData['scopes'];
    
} catch (Exception $e) {
    http_response_code(401);
}
```

#### Zarządzanie kluczami

```php
$auth = new Authorization();
$provider = $auth->getTokenProvider('api_key');
$userId = $auth->getAuthorizedId();

// Lista kluczy użytkownika
$keys = $provider->listUserKeys($userId);

// Detale klucza
$key = $provider->getKey($keyId, $userId);

// Aktualizacja klucza
$provider->updateKey($keyId, $userId, [
    'name' => 'Updated Name',
    'rate_limit' => 5000
]);

// Revocation (deaktywacja)
$auth->revokeToken($apiKey, 'api_key');
```

#### Rate Limiting

```php
$provider = $auth->getTokenProvider('api_key');

$rateLimit = $provider->getRateLimit($apiKey);

// Odpowiedź
header('X-RateLimit-Limit: ' . $rateLimit['limit']);
header('X-RateLimit-Used: ' . $rateLimit['used']);
header('X-RateLimit-Remaining: ' . $rateLimit['remaining']);

if ($rateLimit['remaining'] <= 0) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
}
```

## Dokumentacja

- [JWT + API Keys Guide](JWT_API_KEYS.md) - Comprehensive JWT and API Keys documentation
- [2FA Guide](TWO_FACTOR_AUTH.md) - Two-Factor Authentication implementation
- [GitHub OAuth Guide](GITHUB_OAUTH.md) - GitHub OAuth2 login setup
- [Custom Hasher Guide](CUSTOM_HASHER.md) - Custom password hasher implementation