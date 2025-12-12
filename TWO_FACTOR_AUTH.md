# Dwuetapowa Weryfikacja (2FA) - Przewodnik

Kompletny przewodnik do implementacji i użytkowania dwuetapowej weryfikacji (2FA/MFA) w NimblePHP Authorization.

## Spis treści

1. [Przegląd](#przegląd)
2. [Konfiguracja](#konfiguracja)
3. [TOTP (Google Authenticator)](#totp-google-authenticator)
4. [Email 2FA](#email-2fa)
5. [Przepływ logowania](#przepływ-logowania)
6. [Zarządzanie 2FA](#zarządzanie-2fa)
7. [Kody odzyskania](#kody-odzyskania)
8. [Bezpieczeństwo](#bezpieczeństwo)

## Przegląd

Dwuetapowa weryfikacja dodaje dodatkową warstwę bezpieczeństwa. Po wprowadzeniu prawidłowych hasła/loginu, użytkownik musi potwierdzić swoją tożsamość przy użyciu drugiego czynnika.

### Obsługiwane metody

#### TOTP (Time-based One-Time Password)
- **Co to?** Kody generowane przez aplikacje authenticatora
- **Aplikacje:** Google Authenticator, Microsoft Authenticator, Authy, itp.
- **Bezpieczeństwo:** ⭐⭐⭐⭐⭐ (Najwyższe)
- **Niezawodność:** ⭐⭐⭐⭐⭐ (Działa offline)
- **UX:** ⭐⭐⭐⭐ (Wymaga aplikacji, ale intuicyjne)

#### Email
- **Co to?** Kody wysyłane na adres email
- **Bezpieczeństwo:** ⭐⭐⭐⭐ (Wysokie)
- **Niezawodność:** ⭐⭐⭐ (Zależy od dostawcy email)
- **UX:** ⭐⭐⭐⭐⭐ (Nie wymaga aplikacji)

## Konfiguracja

### 1. Inicjalizacja dostawców

```php
use NimblePHP\Authorization\Config;
use NimblePHP\Authorization\Providers\TOTPProvider;
use NimblePHP\Authorization\Providers\EmailProvider;

// Zarejestruj TOTP provider
Config::registerTwoFactorProvider(
    'totp',
    new TOTPProvider('Moja Aplikacja', 6, 30)
    // Parametry: (issuer, codeLength, timeStep)
);

// Zarejestruj Email provider
$emailProvider = new EmailProvider(6, 600); // 6-cyfrowy kod, ważny 10 minut
$emailProvider->setEmailCallback(function($email, $code) {
    // Implementuj wysyłanie emaila
    sendEmailWithCode($email, $code);
});
Config::registerTwoFactorProvider('email', $emailProvider);
```

### 2. Baza danych

Migracja automatycznie dodaje kolumny:
- `two_factor_secret` - Sekret 2FA
- `two_factor_provider` - Nazwa dostawcy ('totp', 'email')

Jeśli chcesz użyć innych nazw kolumn:

```php
use NimblePHP\Authorization\Config;

Config::$twoFactorColumns = [
    'secret' => 'custom_2fa_secret',
    'provider' => 'custom_2fa_provider',
];
```

## TOTP (Google Authenticator)

### Włączanie 2FA dla użytkownika

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Config;

$auth = new Authorization();

if (!$auth->isAuthorized()) {
    die('Użytkownik nie jest zalogowany');
}

// Pobierz TOTP provider
$totp = Config::getTwoFactorProvider('totp');

// Włącz 2FA
$result = $auth->enableTwoFactorAuth($totp);

// Zwracane dane:
// - secret: String - Sekret (przechowywany już w BD)
// - provider: String - Nazwa dostawcy ('totp')
// - qr_code: String - URL do QR kodu

// Wyświetl QR kod
echo "<img src='{$result['qr_code']}' alt='2FA QR Code'>";
echo "Sekret: {$result['secret']}";
```

### Wyświetlanie QR kodu

QR kod można wyświetlić na kilka sposobów:

#### 1. Obraz z Google Charts (domyślnie)
```php
$qrCodeUrl = $totp->getQRCodeImageURL($secret, 'user@example.com');
echo "<img src='$qrCodeUrl' alt='QR Code'>";
```

#### 2. Wygenerowanie własnego QR kodu
Możesz użyć biblioteki takiej jak `bacon/bacon-qr-code`:

```bash
composer require bacon/bacon-qr-code
```

```php
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Writer;

$renderer = new ImageRenderer(
    new SvgImageBackEnd(),
    new Encoder()
);
$writer = new Writer($renderer);

$uri = $totp->getQRCodeURI($secret, 'user@example.com');
$qrCode = $writer->writeString($uri);

echo $qrCode; // SVG
```

### Weryfikacja kodu podczas logowania

```php
use NimblePHP\Authorization\Authorization;
use NimblePHP\Authorization\Exceptions\PendingTwoFactorException;
use NimblePHP\Authorization\Exceptions\TwoFactorException;

$auth = new Authorization();

try {
    // Krok 1: Normalny login
    $success = $auth->login($_POST['email'], $_POST['password']);
    
    if ($success) {
        // Użytkownik nie ma 2FA
        $_SESSION['logged_in'] = true;
        header('Location: /dashboard');
    }
} catch (PendingTwoFactorException $e) {
    // Krok 2: Użytkownik ma 2FA i musi go potwierdić
    $userId = $e->getUserId();
    $provider = $e->getProvider();
    
    // Przechowaj info w sesji dla strony weryfikacji
    $_SESSION['pending_2fa'] = true;
    
    // Przekieruj do strony weryfikacji 2FA
    header('Location: /verify-2fa');
    exit;
} catch (RateLimitExceededException $e) {
    echo "Zbyt wiele nieudanych prób. Spróbuj za " . $e->getRemainingTime() . " sekund.";
}

// === Na stronie weryfikacji 2FA (/verify-2fa) ===

if (!isset($_SESSION['pending_2fa'])) {
    die('Brak oczekującej weryfikacji 2FA');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $verified = $auth->verifyTwoFactorCode($_POST['2fa_code']);
        
        if ($verified) {
            unset($_SESSION['pending_2fa']);
            $_SESSION['logged_in'] = true;
            header('Location: /dashboard');
            exit;
        }
    } catch (TwoFactorException $e) {
        $error = "Nieprawidłowy kod: " . $e->getMessage();
    } catch (\InvalidArgumentException $e) {
        die("Błąd weryfikacji: " . $e->getMessage());
    }
}

// Wyświetl formularz
?>
<form method="POST">
    <input type="text" name="2fa_code" placeholder="Wpisz kod z authenticatora" required>
    <?php if (isset($error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <button type="submit">Weryfikuj</button>
</form>
```

## Email 2FA

### Konfiguracja sendowania emaila

```php
use NimblePHP\Authorization\Providers\EmailProvider;
use NimblePHP\Authorization\Config;

$emailProvider = new EmailProvider(
    6,      // Długość kodu
    600     // Ważność w sekundach (10 minut)
);

// Ustaw funkcję do wysyłania
$emailProvider->setEmailCallback(function($email, $code) {
    // Opcja 1: Użyj PHPMailer
    $mail = new PHPMailer\PHPMailer\PHPMailer();
    $mail->addAddress($email);
    $mail->setFrom('noreply@example.com');
    $mail->Subject = 'Twój kod weryfikacyjny';
    $mail->Body = "Twój kod weryfikacyjny: $code\n\nKod jest ważny przez 10 minut.";
    $mail->send();
    
    // Opcja 2: Użyj funkcji mail()
    // mail($email, 'Kod weryfikacyjny', "Kod: $code");
});

Config::registerTwoFactorProvider('email', $emailProvider);
```

### Wysłanie kodu na email

```php
use NimblePHP\Authorization\Config;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? null;
    
    if ($email) {
        $emailProvider = Config::getTwoFactorProvider('email');
        $code = $emailProvider->generateCode($email);
        
        // Kod został wysłany via callback
        echo "Kod weryfikacyjny został wysłany na adres $email";
    }
}
```

### Weryfikacja kodu email

Podobnie jak TOTP, ale używasz email provider:

```php
try {
    $verified = $auth->verifyTwoFactorCode($_POST['2fa_code']);
    if ($verified) {
        echo "Zalogowano!";
    }
} catch (TwoFactorException $e) {
    echo "Nieprawidłowy kod: " . $e->getMessage();
}
```

## Przepływ logowania

### Kompletny przykład

```
1. Użytkownik wpisuje email i hasło
   ↓
2. Sprawdzenie Rate Limitingu
   ↓
3. Weryfikacja hasła
   ↓
4. Sprawdzenie czy 2FA jest włączona
   ├─ TAK → PendingTwoFactorException
   │         ↓
   │        Użytkownik wpisuje kod 2FA
   │         ↓
   │        Weryfikacja kodu
   │         ├─ Poprawny → Zalogowanie
   │         └─ Błędny → TwoFactorException
   │
   └─ NIE → Zalogowanie
```

### Diagram stanów

```
+----------------+
|  Niezalogowany |
+-----+----------+
      │
      │ login(email, password)
      ↓
+-------------------+
| Weryfikacja hasła |
+-----+---+-------+-+
      │   │       │
      │   │   RateLimitExceededException
      │   │
      │   UniAuthenticated
      │
      ├─ 2FA wyłączona
      │  ↓
      │  Zalogowany ✓
      │
      └─ 2FA włączona
         ↓
         PendingTwoFactorException
         ↓
         verifyTwoFactorCode(code)
         ├─ Poprawny → Zalogowany ✓
         └─ Błędny → TwoFactorException
```

## Zarządzanie 2FA

### Sprawdzenie czy użytkownik ma 2FA

```php
use NimblePHP\Authorization\Authorization;

$auth = new Authorization();

if ($auth->isAuthorized()) {
    if ($auth->isTwoFactorEnabled()) {
        echo "Użytkownik ma 2FA włączone";
    } else {
        echo "Użytkownik nie ma 2FA";
    }
}
```

### Wyłączenie 2FA

```php
if ($auth->isAuthorized()) {
    if ($auth->disableTwoFactorAuth()) {
        echo "2FA zostało wyłączone";
    }
}
```

### Zmiana metody 2FA

```php
// Wyłącz stary dostawca
$auth->disableTwoFactorAuth();

// Włącz nowego dostawcę
$newProvider = Config::getTwoFactorProvider('email');
$result = $auth->enableTwoFactorAuth($newProvider);
```

## Kody odzyskania

Kody odzyskania pozwalają użytkownikowi zalogować się, jeśli utraci dostęp do swojego authenticatora.

### Generowanie kodów odzyskania

```php
use NimblePHP\Authorization\Config;

$totp = Config::getTwoFactorProvider('totp');
$secret = $userSecret; // Pobierz z bazy danych

// Generuj 10 kodów odzyskania
$recoveryCodes = $totp->getRecoveryCodes($secret, 10);

foreach ($recoveryCodes as $code) {
    echo "Kod: $code\n";
}
```

### Przechowywanie kodów odzyskania

Rekomendujemy przechowywać kody odzyskania w bazie danych:

```php
// Dodaj kolumnę do tabeli accounts
ALTER TABLE accounts ADD COLUMN recovery_codes JSON NULL;

// Przechowuj skrótowane kody
$hashedCodes = array_map(function($code) {
    return hash('sha256', $code);
}, $recoveryCodes);

// Zapisz do bazy
$account->update(['recovery_codes' => json_encode($hashedCodes)]);
```

### Użycie kodu odzyskania podczas logowania

```php
// Użytkownik może wpisać kod odzyskania zamiast kodu 2FA
try {
    // Kod odzyskania jest weryfikowany jako zwykły kod 2FA
    $verified = $auth->verifyTwoFactorCode($_POST['2fa_code']);
    
    if ($verified) {
        // Usuń użyty kod z bazy danych
        removeUsedRecoveryCode($auth->getAuthorizedId(), $_POST['2fa_code']);
        
        echo "Zalogowano za pomocą kodu odzyskania";
    }
} catch (TwoFactorException $e) {
    echo "Nieprawidłowy kod";
}
```

## Bezpieczeństwo

### Najlepsze praktyki

#### 1. Szanuj rate limiting
```php
// Nie wyłączaj rate limitingu dla logowania z 2FA
Config::$rateLimitEnabled = true;
Config::$rateLimitMaxAttempts = 5;
```

#### 2. Przechowuj sekrety bezpiecznie
```php
// DOBRZE - sekret jest hashowany
// ŹLE - przechowywanie na kliencie
echo $secret; // ✗ Nie rób tego!
```

#### 3. Używaj HTTPS
```php
// 2FA powinno być używane wyłącznie przez HTTPS
// Skonfiguruj w .htaccess lub nginx
```

#### 4. Logowanie i monitoring
```php
// Loguj każdą próbę weryfikacji 2FA
function log2FAAttempt($userId, $success) {
    $status = $success ? 'SUCCESS' : 'FAILED';
    error_log("2FA $status for user $userId at " . date('Y-m-d H:i:s'));
}
```

#### 5. Wymagaj potwierdzenia zmian
```php
// Gdy użytkownik wyłącza 2FA, wymagaj 2FA
if ($auth->isAuthorized()) {
    // Wymagaj weryfikacji 2FA przed wyłączeniem
    verifyTwoFactor();
    $auth->disableTwoFactorAuth();
}
```

### Chroniące przed atakami

#### Brute Force
- Rate limiting na weryfikację 2FA
- Blokowanie po N nieudanych próbach
- Logarytmiczne opóźnienia między próbami

```php
// Implementuj opóźnienie
$emailProvider = new EmailProvider(6, 600);
$emailProvider->maxAttempts = 5; // Blokuj po 5 próbach
```

#### Man-in-the-Middle
- Zawsze używaj HTTPS
- Sprawdzaj domeny w otpauth:// URI
- Weryfikuj certyfikaty SSL

#### Phishing
- Użytkownicy mogą pomylić sekrety
- Pokaż identyfikator aplikacji w authenticatorze
- Wymagaj kodów odzyskania w bezpiecznym miejscu

### Audyt

```php
// Przechowuj historię 2FA
CREATE TABLE two_factor_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(50), -- 'enable', 'disable', 'verify_success', 'verify_failed'
    provider VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Rozwiązywanie problemów

### Problem: Kody się nie zgadzają

**Przyczyna:** Zegar serwera i urządzenia użytkownika są zsynchronizowane

**Rozwiązanie:**
```php
// Zwiększ tolerancję czasową
$totp = new TOTPProvider();
$totp->discrepancy = 2; // Zamiast 1
```

### Problem: Kod 2FA trwa zbyt długo

**Przyczyna:** Domyślnie kod jest ważny 30 sekund

**Rozwiązanie:**
```php
$emailProvider = new EmailProvider(6, 1800); // 30 minut
```

### Problem: Nie mogę wysłać emaila

**Przyczyna:** Callback nie jest ustawiony lub zawodny

**Rozwiązanie:**
```php
$emailProvider->setEmailCallback(function($email, $code) {
    try {
        // Debugowanie
        error_log("Sending 2FA code to $email");
        
        // Wysyłanie
        mail($email, 'Code', $code);
    } catch (Exception $e) {
        error_log("Failed to send email: " . $e->getMessage());
        throw $e;
    }
});
```

## API Referance

### Authorization

- `enableTwoFactorAuth(TwoFactorProvider $provider): array`
- `verifyTwoFactorCode(string $code, ?string $userId = null): bool`
- `disableTwoFactorAuth(): bool`
- `isTwoFactorEnabled(?int $userId = null): bool`
- `getPendingTwoFactorUserId(): ?int`
- `createPendingTwoFactorState(int $userId, string $providerName): void`

### TOTPProvider

- `generateSecret(): string`
- `generateCode(string $secret): string`
- `verify(string $secret, string $code): bool`
- `isCodeValid(string $secret, string $code): bool`
- `getName(): string` → `'totp'`
- `getQRCodeURI(string $secret, string $accountName, ?string $issuer = null): string`
- `getQRCodeImageURL(string $secret, string $accountName, int $size = 300, ?string $issuer = null): string`
- `getRecoveryCodes(string $secret, int $count = 10): array`
- `verifyRecoveryCode(string $secret, string $code): bool`

### EmailProvider

- `setEmailCallback(callable $callback): void`
- `generateSecret(): string` → `''`
- `generateCode(string $secret): string` → wysyła email
- `verify(string $secret, string $code): bool`
- `isCodeValid(string $secret, string $code): bool`
- `getName(): string` → `'email'`
- `getRemainingTime(string $email): int`
- `clearCode(string $email): void`

### Config

- `registerTwoFactorProvider(string $name, TwoFactorProvider $provider): void`
- `getTwoFactorProvider(string $name): ?TwoFactorProvider`
- `getTwoFactorProviders(): array`
- `getTwoFactorSecretColumn(): string`
- `getTwoFactorProviderColumn(): string`

