# NimblePHP Authorization

Biblioteka autoryzacyjna dla frameworka NimblePHP, dostarczająca kompletny system zarządzania użytkownikami z bezpiecznym hashowaniem haseł.

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
```

### Programistyczna konfiguracja

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