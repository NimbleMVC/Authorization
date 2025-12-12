# Custom Password Hasher

Biblioteka NimblePHP Authorization pozwala na implementację własnego algorytmu szyfrowania haseł.

## Interfejs PasswordHasher

Każdy custom hasher musi implementować interface `PasswordHasher`:

```php
interface PasswordHasher
{
    /**
     * Hash a password
     */
    public function hash(string $password): string;

    /**
     * Verify password against hash
     */
    public function verify(string $hash, string $password): bool;

    /**
     * Check if hash needs rehashing
     */
    public function needsRehash(string $hash): bool;
}
```

## Dostępne Implementacje

### 1. DefaultPasswordHasher (domyślna)

Używa biblioteki `krzysztofzylka/hash` (VersionedHasher).

```php
use NimblePHP\Authorization\Hashers\DefaultPasswordHasher;
use NimblePHP\Authorization\Config;

// Automatycznie ustawiana, opcjonalnie:
Config::setPasswordHasher(new DefaultPasswordHasher());
```

### 2. BcryptPasswordHasher

Implementacja korzystająca z PHP `password_hash` z algorytmem Bcrypt.

```php
use NimblePHP\Authorization\Hashers\BcryptPasswordHasher;
use NimblePHP\Authorization\Config;

// Cost 12 = domyślnie (4-31)
Config::setPasswordHasher(new BcryptPasswordHasher(cost: 12));
```

**Parametry:**
- `cost` (4-31): Im wyższa wartość, tym bardziej bezpieczne, ale wolniejsze (domyślnie: 12)

### 3. ArgonPasswordHasher

Najnowsza i najbardziej bezpieczna implementacja (PASSWORD_ARGON2ID).

```php
use NimblePHP\Authorization\Hashers\ArgonPasswordHasher;
use NimblePHP\Authorization\Config;

Config::setPasswordHasher(new ArgonPasswordHasher(
    algorithm: PASSWORD_ARGON2ID,
    memoryLimit: 65536,
    timeCost: 4,
    parallelism: 1
));
```

**Parametry:**
- `algorithm`: PASSWORD_ARGON2I lub PASSWORD_ARGON2ID (domyślnie: PASSWORD_ARGON2ID)
- `memoryLimit`: Limit pamięci w KiB (domyślnie: 65536)
- `timeCost`: Iteracje (domyślnie: 4)
- `parallelism`: Liczba wątków (domyślnie: 1)

## Tworzenie Custom Hasher'a

### Krok 1: Utwórz klasę implementującą PasswordHasher

```php
<?php

namespace App\Auth;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

class MyCustomHasher implements PasswordHasher
{
    public function hash(string $password): string
    {
        // Twoja implementacja haszowania
        return hash('sha256', $password);
    }

    public function verify(string $hash, string $password): bool
    {
        // Twoja implementacja weryfikacji
        return hash_equals($hash, hash('sha256', $password));
    }

    public function needsRehash(string $hash): bool
    {
        // Zwróć true jeśli hash powinien być zaktualizowany
        return false;
    }
}
```

### Krok 2: Skonfiguruj w aplikacji

```php
use App\Auth\MyCustomHasher;
use NimblePHP\Authorization\Config;

// W bootstrapie aplikacji
Config::setPasswordHasher(new MyCustomHasher());
```

## Przykłady Implementacji

### SHA-256 z Solą

```php
<?php

namespace App\Auth;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

class SHA256Hasher implements PasswordHasher
{
    public function hash(string $password): string
    {
        $salt = bin2hex(random_bytes(16));
        $hash = hash('sha256', $salt . $password);
        return '$sha256$' . $salt . '$' . $hash;
    }

    public function verify(string $hash, string $password): bool
    {
        $parts = explode('$', $hash);
        if (count($parts) < 4) return false;
        
        $salt = $parts[2];
        $storedHash = $parts[3];
        
        $computedHash = hash('sha256', $salt . $password);
        return hash_equals($storedHash, $computedHash);
    }

    public function needsRehash(string $hash): bool
    {
        return !str_starts_with($hash, '$sha256$');
    }
}
```

### PBKDF2

```php
<?php

namespace App\Auth;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

class PBKDF2Hasher implements PasswordHasher
{
    private int $iterations = 100000;
    private string $algorithm = 'sha256';

    public function hash(string $password): string
    {
        $salt = bin2hex(random_bytes(16));
        $hash = hash_pbkdf2(
            $this->algorithm,
            $password,
            $salt,
            $this->iterations,
            64
        );
        return '$pbkdf2$' . $this->iterations . '$' . $salt . '$' . $hash;
    }

    public function verify(string $hash, string $password): bool
    {
        $parts = explode('$', $hash);
        if (count($parts) < 5) return false;
        
        $iterations = (int)$parts[2];
        $salt = $parts[3];
        $storedHash = $parts[4];
        
        $computedHash = hash_pbkdf2(
            $this->algorithm,
            $password,
            $salt,
            $iterations,
            64
        );
        
        return hash_equals($storedHash, $computedHash);
    }

    public function needsRehash(string $hash): bool
    {
        $parts = explode('$', $hash);
        if (count($parts) < 3) return true;
        
        $iterations = (int)$parts[2];
        return $iterations < $this->iterations;
    }
}
```

### Integracja z LDAP

```php
<?php

namespace App\Auth;

use NimblePHP\Authorization\Interfaces\PasswordHasher;

class LDAPHasher implements PasswordHasher
{
    private string $ldapServer;

    public function __construct(string $ldapServer)
    {
        $this->ldapServer = $ldapServer;
    }

    public function hash(string $password): string
    {
        // LDAP nie przechowuje haseł - zwróć placeholder
        return 'ldap:' . bin2hex(random_bytes(16));
    }

    public function verify(string $hash, string $password): bool
    {
        // Weryfikuj bezpośrednio w LDAP
        $ldap = ldap_connect($this->ldapServer);
        if (!$ldap) return false;
        
        // Twoja logika uwierzytelniania LDAP
        return $this->ldapAuth($ldap, $password);
    }

    public function needsRehash(string $hash): bool
    {
        return false;
    }

    private function ldapAuth($ldap, string $password): bool
    {
        // Implementacja uwierzytelniania LDAP
        return true;
    }
}
```

## Migracja Istniejących Haseł

Aby zmienić algorytm dla istniejących haseł, ustaw `needsRehash()` aby zwracał `true` dla starych haseł:

```php
public function needsRehash(string $hash): bool
{
    // Jeśli hash nie używa nowego algorytmu, trzeba go wymienić
    return !str_starts_with($hash, '$newformat$');
}
```

Hasła zostaną automatycznie ponownie zhashowane przy następnym logowaniu.

## Best Practices

1. **Nigdy nie przechowuj plaintext haseł**
2. **Używaj randomowych soli** dla każdego hasła
3. **Porównuj hashe za pomocą `hash_equals()`** aby uniknąć timing attack'ów
4. **Implementuj `needsRehash()`** dla migracji algorytmów
5. **Testuj swoją implementację** na bezpieczeństwo
6. **Dokumentuj parametry** Twojego algorytmu

## Security Considerations

### Timing Attacks
Zawsze używaj `hash_equals()` do porównania:

```php
// ✅ Bezpieczne
return hash_equals($storedHash, $computedHash);

// ❌ Niebezpieczne
return $storedHash === $computedHash;
```

### Password Stretching
Używaj algorytmów z iteracjami/cost:

```php
// Bcrypt: cost parameter
// Argon2: iterations + memory
// PBKDF2: liczba iteracji
```

### Salt Management
- Generuj nową sól dla każdego hasła
- Przechowuj sól razem z hashem
- Używaj `random_bytes()` do generowania soli

## Testing

```php
<?php

use App\Auth\MyCustomHasher;
use PHPUnit\Framework\TestCase;

class MyCustomHasherTest extends TestCase
{
    private MyCustomHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new MyCustomHasher();
    }

    public function testHashPassword(): void
    {
        $password = 'SecurePassword123!';
        $hash = $this->hasher->hash($password);
        
        $this->assertIsString($hash);
        $this->assertNotEmpty($hash);
        $this->assertNotEquals($password, $hash);
    }

    public function testVerifyPassword(): void
    {
        $password = 'SecurePassword123!';
        $hash = $this->hasher->hash($password);
        
        $this->assertTrue($this->hasher->verify($hash, $password));
        $this->assertFalse($this->hasher->verify($hash, 'WrongPassword'));
    }

    public function testNeedsRehash(): void
    {
        $password = 'TestPassword';
        $hash = $this->hasher->hash($password);
        
        $this->assertFalse($this->hasher->needsRehash($hash));
    }
}
```

## Linki

- [PHP password_hash](https://www.php.net/manual/en/function.password-hash.php)
- [PHP hash_pbkdf2](https://www.php.net/manual/en/function.hash-pbkdf2.php)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
