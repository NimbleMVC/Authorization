<?php

return [
    'validation' => [
        'username_empty' => 'Nazwa użytkownika nie może być pusta',
        'username_exists' => 'Nazwa użytkownika już istnieje',
        'email_empty' => 'Email nie może być pusty',
        'email_invalid' => 'Nieprawidłowy format email',
        'email_exists' => 'Email już istnieje',
        'password_empty' => 'Hasło nie może być puste',
        'password_too_short' => 'Hasło musi mieć co najmniej 6 znaków',
        'login_empty' => '{field} nie może być puste',
        'credentials_empty' => 'Nazwa użytkownika i hasło nie mogą być puste',
        'invalid_credentials' => 'Nieprawidłowa nazwa użytkownika lub hasło',
        'account_not_activated' => 'Konto nie zostało aktywowane',
        'authorization_header_missing' => 'Brak nagłówka autoryzacji',
    ],
    'auth' => [
        'user_must_be_authenticated_2fa_enable' => 'Użytkownik musi być zalogowany, aby włączyć 2FA',
        'user_must_be_authenticated_2fa_disable' => 'Użytkownik musi być zalogowany, aby wyłączyć 2FA',
        'no_pending_2fa' => 'Brak oczekującej weryfikacji 2FA',
        'user_id_mismatch' => 'Niezgodność ID użytkownika',
        '2fa_provider_not_configured' => 'Dostawca 2FA nie jest skonfigurowany: {provider}',
        'user_not_found' => 'Nie znaleziono użytkownika',
        '2fa_not_enabled' => '2FA nie jest włączone dla użytkownika',
    ],
];
