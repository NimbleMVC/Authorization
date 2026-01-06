<?php

namespace NimblePHP\Authorization;

use InvalidArgumentException;
use krzysztofzylka\DatabaseManager\Exception\DatabaseManagerException;
use krzysztofzylka\DatabaseManager\Table;
use Krzysztofzylka\Hash\VersionedHasher;
use NimblePHP\Authorization\Exceptions\RateLimitExceededException;
use NimblePHP\Authorization\Exceptions\TwoFactorException;
use NimblePHP\Authorization\Exceptions\PendingTwoFactorException;
use NimblePHP\Authorization\Exceptions\ValidationException;
use NimblePHP\Authorization\Interfaces\TwoFactorProvider;
use NimblePHP\Authorization\Interfaces\OAuthProvider;
use NimblePHP\Authorization\Interfaces\TokenProvider;
use NimblePHP\Framework\Kernel;
use NimblePHP\Framework\Session;

/**
 * Authorization class - Main authorization service for user authentication and authorization
 * 
 * This class provides methods for:
 * - User authentication (login/logout/register)
 * - Permission and role checking
 * - Session management for authenticated users
 * 
 * @package NimblePHP\Authorization
 */
class Authorization
{

    /**
     * Session instance
     * @var Session
     */
    private Session $session;

    /**
     * Account instance for database operations
     * @var Account
     */
    private Account $account;

    /**
     * RateLimiter instance for brute force protection
     * @var RateLimiter
     */
    private RateLimiter $rateLimiter;

    /**
     * Construct the Authorization instance
     */
    public function __construct()
    {
        $this->session = Kernel::$serviceContainer->get('kernel.session');
        $this->account = new Account();
        $this->rateLimiter = new RateLimiter();
    }

    /**
     * Check if the user is authorized
     * @return bool
     */
    public function isAuthorized(): bool
    {
        return $this->session->exists(Config::$sessionKey) && is_int($this->session->get(Config::$sessionKey));
    }

    /**
     * Get the authorized id
     * @return int
     */
    public function getAuthorizedId(): int
    {
        return (int)$this->session->get(Config::$sessionKey);
    }

    /**
     * Get the current user account data
     * @return array|null
     */
    public function getCurrentUser(): ?array
    {
        if (!$this->isAuthorized()) {
            return null;
        }

        return $this->account->find([Config::getColumn('id') => $this->getAuthorizedId()]);
    }

    /**
     * Register the user
     * @param string $username
     * @param string $password
     * @param string|null $email
     * @return bool
     * @throws DatabaseManagerException
     */
    public function register(string $username, string $password, ?string $email = null): bool
    {
        if (Config::isUsernameAuth()) {
            if (empty(trim($username))) {
                throw new ValidationException(Lang::get('validation.username_empty'));
            }

            if ($this->account->userExists(identifier: $username)) {
                throw new ValidationException(Lang::get('validation.username_exists'));
            }
        } elseif (Config::isEmailAuth()) {
            if (empty(trim($email))) {
                throw new ValidationException(Lang::get('validation.email_empty'));
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new ValidationException(Lang::get('validation.email_invalid'));
            }

            if ($this->account->emailExists($email)) {
                throw new ValidationException(Lang::get('validation.email_exists'));
            }
        }

        if (strlen($password) < 6) {
            throw new ValidationException(Lang::get('validation.password_too_short'));
        }

        // Hash password using configured hasher
        $passwordHasher = Config::getPasswordHasher();
        $hashedPassword = $passwordHasher->hash($password);

        $data = [
            Config::getColumn('username') => $username,
            Config::getColumn('password') => $hashedPassword,
        ];

        if ($email) {
            $data[Config::getColumn('email')] = $email;
        }

        $data[Config::getColumn('active')] = Config::isActivationRequired() ? 0 : 1;

        return $this->account->insert($data);
    }

    /**
     * Login the user
     * @param string $login
     * @param string $password
     * @return bool
     * @throws ValidationException If validation fails
     * @throws RateLimitExceededException If rate limit exceeded
     * @throws DatabaseManagerException
     */
    public function login(string $login, string $password): bool
    {
        if (empty(trim($login))) {
            $field = Config::isEmailAuth() ? 'Email' : 'Username';
            throw new ValidationException(Lang::get('validation.login_empty', ['field' => $field]));
        }

        if (empty($password)) {
            throw new ValidationException(Lang::get('validation.password_empty'));
        }

        // Check rate limiting
        if (Config::isRateLimitEnabled() && $this->rateLimiter->isRateLimited($login)) {
            $remaining = $this->rateLimiter->getLockoutTimeRemaining($login);
            throw new RateLimitExceededException("Too many login attempts. Please try again in {$remaining} seconds.", $remaining);
        }

        $conditions = [];

        if (Config::isEmailAuth()) {
            if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
                throw new ValidationException(Lang::get('validation.email_invalid'));
            }

            $conditions[Config::getColumn('email')] = $login;
        } else {
            $conditions[Config::getColumn('username')] = $login;
        }

        $account = $this->account->find($conditions);

        if (!$account) {
            // Record failed attempt
            if (Config::isRateLimitEnabled()) {
                $this->rateLimiter->recordFailedAttempt($login);
            }
            return false;
        }

        if (!VersionedHasher::verify($account[Config::$tableName][Config::getColumn('password')], $password)) {
            // Record failed attempt
            if (Config::isRateLimitEnabled()) {
                $this->rateLimiter->recordFailedAttempt($login);
            }
            return false;
        }

        if (Config::isActivationRequired() && empty($account[Config::$tableName][Config::getColumn('active')])) {
            // Record failed attempt for inactive account
            if (Config::isRateLimitEnabled()) {
                $this->rateLimiter->recordFailedAttempt($login);
            }
            return false;
        }

        $this->account->setId($account[Config::$tableName][Config::getColumn('id')]);

        // Check if password needs rehashing and update if necessary
        $passwordHasher = Config::getPasswordHasher();
        if ($passwordHasher->needsRehash($account[Config::$tableName][Config::getColumn('password')])) {
            $this->account->changePassword($password);
        }

        // Successful login - clear rate limit
        if (Config::isRateLimitEnabled()) {
            $this->rateLimiter->clearAttempts($login);
        }

        $this->session->set(Config::$sessionKey, $account[Config::$tableName][Config::getColumn('id')]);

        return true;
    }

    /**
     * Authenticate user using HTTP Basic Authentication
     *
     * Parses Authorization header with Basic scheme (RFC 7617).
     * Format: Authorization: Basic base64(username:password)
     *
     * @param bool $send401OnFailure Whether to send 401 header on auth failure
     * @return bool True if authentication successful
     * @throws InvalidArgumentException If Authorization header is invalid
     * @throws RateLimitExceededException If rate limit exceeded
     * @throws DatabaseManagerException
     */
    public function authenticateHttpBasic(bool $send401OnFailure = true): bool
    {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

        if (empty($authHeader)) {
            if ($send401OnFailure) {
                header('HTTP/1.1 401 Unauthorized');
                header('WWW-Authenticate: Basic realm="' . Config::$authType . '"');
            }
            return false;
        }

        if (strpos($authHeader, 'Basic ') !== 0) {
            throw new InvalidArgumentException('Invalid Authorization header format');
        }

        $credentials = base64_decode(substr($authHeader, 6), true);

        if ($credentials === false) {
            throw new InvalidArgumentException('Invalid base64 encoding in Authorization header');
        }

        $parts = explode(':', $credentials, 2);

        if (count($parts) !== 2) {
            throw new InvalidArgumentException('Invalid credentials format in Authorization header');
        }

        list($login, $password) = $parts;

        if (empty($login) || empty($password)) {
            throw new ValidationException(Lang::get('validation.credentials_empty'));
        }

        try {
            return $this->login($login, $password);
        } catch (RateLimitExceededException $e) {
            if ($send401OnFailure) {
                header('HTTP/1.1 429 Too Many Requests');
            }
            throw $e;
        } catch (\Exception $e) {
            if ($send401OnFailure) {
                header('HTTP/1.1 401 Unauthorized');
            }
            throw $e;
        }
    }

    /**
     * Logout the user
     * @return void
     */
    public function logout(): void
    {
        $this->session->remove(Config::$sessionKey);
        $this->session->remove(Config::$twoFactorSessionKey);
        $this->session->remove(Config::$twoFactorProviderSessionKey);
    }

    /**
     * Enable 2FA for the currently authenticated user
     *
     * @param TwoFactorProvider $provider The 2FA provider to use
     * @return array{secret: string, qr_code: ?string} Array with secret and QR code URL (if applicable)
     * @throws InvalidArgumentException If user not authenticated
     * @throws DatabaseManagerException
     */
    public function enableTwoFactorAuth(TwoFactorProvider $provider): array
    {
        if (!$this->isAuthorized()) {
            throw new InvalidArgumentException(Lang::get('auth.user_must_be_authenticated_2fa_enable'));
        }

        $userId = $this->getAuthorizedId();
        $secret = $provider->generateSecret();

        // Store 2FA secret for user
        $this->account->setId($userId);
        $this->account->updateTwoFactorSecret($secret, $provider->getName());

        $result = [
            'secret' => $secret,
            'provider' => $provider->getName(),
            'qr_code' => null,
        ];

        // Generate QR code for TOTP provider
        if (method_exists($provider, 'getQRCodeImageURL')) {
            $user = $this->account->find([Config::getColumn('id') => $userId]);
            $userIdentifier = Config::isEmailAuth() 
                ? $user[Config::$tableName][Config::getColumn('email')] 
                : $user[Config::$tableName][Config::getColumn('username')];
            
            $result['qr_code'] = $provider->getQRCodeImageURL($secret, $userIdentifier);
        }

        return $result;
    }

    /**
     * Verify 2FA code after successful login credentials
     *
     * This creates a pending 2FA state that must be verified before completing login.
     * Returns true if 2FA verification is complete and user is logged in.
     *
     * @param string $code The 2FA code to verify
     * @param string|null $userId Optional user ID if verifying for a specific user
     * @return bool True if 2FA code is valid and user is authenticated
     * @throws TwoFactorException If code is invalid or expired
     * @throws InvalidArgumentException If no pending 2FA verification
     * @throws DatabaseManagerException
     */
    public function verifyTwoFactorCode(string $code, ?string $userId = null): bool
    {
        // Check if there's a pending 2FA verification
        if (!$this->session->exists(Config::$twoFactorSessionKey)) {
            throw new InvalidArgumentException(Lang::get('auth.no_pending_2fa'));
        }

        $pendingUserId = $this->session->get(Config::$twoFactorSessionKey);
        $providerName = $this->session->get(Config::$twoFactorProviderSessionKey);

        // Verify the user ID matches if provided
        if ($userId !== null && (int)$userId !== $pendingUserId) {
            throw new InvalidArgumentException(Lang::get('auth.user_id_mismatch'));
        }

        // Get the 2FA provider
        $provider = Config::getTwoFactorProvider($providerName);
        if (!$provider) {
            throw new InvalidArgumentException(Lang::get('auth.2fa_provider_not_configured', ['provider' => $providerName]));
        }

        // Get user's 2FA secret
        $this->account->setId($pendingUserId);
        $userAccount = $this->account->getAccount();

        if (!$userAccount) {
            $this->session->remove(Config::$twoFactorSessionKey);
            $this->session->remove(Config::$twoFactorProviderSessionKey);
            throw new InvalidArgumentException(Lang::get('auth.user_not_found'));
        }

        $secret = $userAccount[Config::$tableName][Config::getTwoFactorSecretColumn()] ?? null;

        if (!$secret) {
            $this->session->remove(Config::$twoFactorSessionKey);
            $this->session->remove(Config::$twoFactorProviderSessionKey);
            throw new InvalidArgumentException(Lang::get('auth.2fa_not_enabled'));
        }

        // Verify the code
        if (!$provider->verify($secret, $code)) {
            // Check if it's a recovery code
            if (!$provider->verifyRecoveryCode($secret, $code)) {
                throw new TwoFactorException('Invalid or expired 2FA code');
            }
        }

        // Code verified successfully - complete the login
        $this->session->set(Config::$sessionKey, $pendingUserId);
        $this->session->remove(Config::$twoFactorSessionKey);
        $this->session->remove(Config::$twoFactorProviderSessionKey);

        return true;
    }

    /**
     * Disable 2FA for the currently authenticated user
     *
     * @return bool True if 2FA was successfully disabled
     * @throws InvalidArgumentException If user not authenticated
     * @throws DatabaseManagerException
     */
    public function disableTwoFactorAuth(): bool
    {
        if (!$this->isAuthorized()) {
            throw new InvalidArgumentException(Lang::get('auth.user_must_be_authenticated_2fa_disable'));
        }

        $userId = $this->getAuthorizedId();
        $this->account->setId($userId);

        return $this->account->clearTwoFactorSecret();
    }

    /**
     * Check if user has 2FA enabled
     *
     * @param int|null $userId User ID (if null, uses currently authenticated user)
     * @return bool True if user has 2FA enabled
     * @throws DatabaseManagerException
     */
    public function isTwoFactorEnabled(?int $userId = null): bool
    {
        if ($userId === null) {
            if (!$this->isAuthorized()) {
                return false;
            }
            $userId = $this->getAuthorizedId();
        }

        $user = $this->account->find([Config::getColumn('id') => $userId]);
        if (!$user) {
            return false;
        }

        $secret = $user[Config::$tableName][Config::getTwoFactorSecretColumn()] ?? null;
        return !empty($secret);
    }

    /**
     * Get currently pending 2FA user ID
     *
     * @return int|null The user ID if 2FA is pending, null otherwise
     */
    public function getPendingTwoFactorUserId(): ?int
    {
        if (!$this->session->exists(Config::$twoFactorSessionKey)) {
            return null;
        }

        return (int)$this->session->get(Config::$twoFactorSessionKey);
    }

    /**
     * Create a pending 2FA verification state during login
     *
     * Called internally after credentials are verified but before 2FA is complete.
     *
     * @param int $userId The user ID
     * @param string $providerName The 2FA provider name
     * @throws DatabaseManagerException
     */
    public function createPendingTwoFactorState(int $userId, string $providerName): void
    {
        $this->session->set(Config::$twoFactorSessionKey, $userId);
        $this->session->set(Config::$twoFactorProviderSessionKey, $providerName);
    }

    /**
     * Check if user has specific role
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->userHasRole($userId);
    }

    /**
     * Check if user has specific permission
     * @param string $permissionName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasPermission(string $permissionName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userRoles = $this->getUserRoles();

        foreach ($userRoles as $roleData) {
            $role = new Role($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);
            $permissions = $role->getPermissions();

            foreach ($permissions as $permission) {
                if ($permission[Config::getPermissionTableName()][Config::getPermissionColumn('name')] === $permissionName) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has any of the specified roles
     * @param array $roleNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAnyRole(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if ($this->hasRole($roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified roles
     * @param array $roleNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAllRoles(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if (!$this->hasRole($roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if user has any of the specified permissions
     * @param array $permissionNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAnyPermission(array $permissionNames): bool
    {
        foreach ($permissionNames as $permissionName) {
            if ($this->hasPermission($permissionName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified permissions
     * @param array $permissionNames
     * @return bool
     * @throws DatabaseManagerException
     */
    public function hasAllPermissions(array $permissionNames): bool
    {
        foreach ($permissionNames as $permissionName) {
            if (!$this->hasPermission($permissionName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all roles for current user
     * @return array
     * @throws DatabaseManagerException
     */
    public function getUserRoles(): array
    {
        if (!$this->isAuthorized()) {
            return [];
        }

        $userId = $this->getAuthorizedId();
        $userRolesTable = new Table(Config::getUserRoleTableName());

        $userRoles = $userRolesTable->findAll([
            Config::getUserRoleColumn('user_id') => $userId
        ]) ?? [];

        $roles = [];
        $rolesTable = new Table(Config::getRoleTableName());

        foreach ($userRoles as $userRole) {
            $roleId = $userRole[Config::getUserRoleTableName()][Config::getUserRoleColumn('role_id')];
            $role = $rolesTable->find([Config::getRoleColumn('id') => $roleId]);

            if ($role) {
                $roles[] = $role;
            }
        }

        return $roles;
    }

    /**
     * Get all permissions for current user
     * @return array
     * @throws DatabaseManagerException
     */
    public function getUserPermissions(): array
    {
        if (!$this->isAuthorized()) {
            return [];
        }

        $userRoles = $this->getUserRoles();
        $permissions = [];

        foreach ($userRoles as $roleData) {
            $role = new Role($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);
            $rolePermissions = $role->getPermissions();

            foreach ($rolePermissions as $permission) {
                $permissionName = $permission[Config::getPermissionTableName()][Config::getPermissionColumn('name')];

                if (!in_array($permissionName, array_column($permissions, Config::getPermissionTableName() . '.' . Config::getPermissionColumn('name')))) {
                    $permissions[] = $permission;
                }
            }
        }

        return $permissions;
    }

    /**
     * Assign role to current user
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function assignRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->assignToUser($userId);
    }

    /**
     * Remove role from current user
     * @param string $roleName
     * @return bool
     * @throws DatabaseManagerException
     */
    public function removeRole(string $roleName): bool
    {
        if (!$this->isAuthorized()) {
            return false;
        }

        $userId = $this->getAuthorizedId();
        $role = new Role();
        $roleData = $role->findByName($roleName);

        if (!$roleData) {
            return false;
        }

        $role->setId($roleData[Config::getRoleTableName()][Config::getRoleColumn('id')]);

        return $role->removeFromUser($userId);
    }

    /**
     * Get remaining login attempts for identifier
     * 
     * Used to display attempt count to user during login process
     * 
     * @param string $identifier Username or email
     * @return int Remaining attempts before lockout
     */
    public function getRemainingLoginAttempts(string $identifier): int
    {
        if (!Config::isRateLimitEnabled()) {
            return Config::getRateLimitMaxAttempts();
        }

        return $this->rateLimiter->getRemainingAttempts($identifier);
    }

    /**
     * Get lockout time remaining for identifier
     * 
     * Used to display lockout duration to user
     * 
     * @param string $identifier Username or email
     * @return int Seconds remaining in lockout (0 if not locked)
     */
    public function getLoginLockoutTimeRemaining(string $identifier): int
    {
        if (!Config::isRateLimitEnabled()) {
            return 0;
        }

        return $this->rateLimiter->getLockoutTimeRemaining($identifier);
    }

    /**
     * Check if login is rate limited for identifier
     * 
     * @param string $identifier Username or email
     * @return bool True if rate limited, false otherwise
     */
    public function isLoginRateLimited(string $identifier): bool
    {
        if (!Config::isRateLimitEnabled()) {
            return false;
        }

        return $this->rateLimiter->isRateLimited($identifier);
    }

    /**
     * Get OAuth provider by name
     * 
     * @param string $name Provider name (e.g., 'github')
     * @return OAuthProvider OAuth provider instance
     * @throws InvalidArgumentException If provider not registered
     */
    public function getOAuthProvider(string $name): OAuthProvider
    {
        return Config::getOAuthProvider($name);
    }

    /**
     * Initiate OAuth login flow
     * 
     * Generates authorization URL and saves state for validation
     * 
     * @param string $providerName OAuth provider name
     * @param string $redirectUri Callback URL
     * @return string Authorization URL to redirect user to
     * @throws InvalidArgumentException If provider not registered
     */
    public function initiateOAuthLogin(string $providerName, string $redirectUri): string
    {
        $provider = $this->getOAuthProvider($providerName);
        $authUrl = $provider->getAuthorizationUrl($redirectUri);
        
        $this->session->set('oauth_provider', $providerName);
        $this->session->set('oauth_redirect_uri', $redirectUri);
        
        return $authUrl;
    }

    /**
     * Handle OAuth callback from provider
     * 
     * Exchanges authorization code for access token and retrieves user data
     * 
     * @param string $code Authorization code from provider
     * @param string $providerName OAuth provider name
     * @return array User data from OAuth provider
     * @throws InvalidArgumentException If provider not registered
     * @throws \Exception If token exchange fails
     */
    public function handleOAuthCallback(string $code, string $providerName): array
    {
        $provider = $this->getOAuthProvider($providerName);
        $redirectUri = $this->session->get('oauth_redirect_uri');
        
        if (!$redirectUri) {
            throw new \Exception('OAuth session expired. Please try again.');
        }
        
        $accessToken = $provider->exchangeCodeForToken($code, $redirectUri);
        $userData = $provider->getUserData($accessToken);
        
        $this->session->remove('oauth_provider');
        $this->session->remove('oauth_redirect_uri');
        
        return array_merge($userData, ['provider' => $providerName]);
    }

    /**
     * Login user via OAuth provider
     * 
     * Creates account if user doesn't exist, or logs in existing user
     * Supports account linking via email matching
     * 
     * @param array $oauthData User data from OAuth provider (must include: oauth_id, email, username, provider)
     * @param bool $createIfNotExists Create account if user doesn't exist (default: true)
     * @return bool True if login successful
     * @throws \Exception If user not found and createIfNotExists is false
     */
    public function loginWithOAuth(array $oauthData, bool $createIfNotExists = true): bool
    {
        $tableName = Config::getTableName();
        $oauthIdColumn = Config::getOAuthColumn('id');
        $oauthProviderColumn = Config::getOAuthColumn('provider');
        
        $accountTable = new Table($tableName);
        
        $existingUser = $accountTable->findByField($oauthIdColumn, $oauthData['oauth_id']);
        
        if (!$existingUser) {
            $existingUser = $accountTable->findByField('email', $oauthData['email'] ?? '');
        }
        
        if (!$existingUser) {
            if (!$createIfNotExists) {
                throw new \Exception('User not found and account creation is disabled.');
            }
            
            $accountData = [
                'username' => $oauthData['username'],
                'email' => $oauthData['email'] ?? '',
                $oauthIdColumn => $oauthData['oauth_id'],
                $oauthProviderColumn => $oauthData['provider'],
                'password' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT),
                'active' => 1,
                'created_at' => date('Y-m-d H:i:s')
            ];
            
            $accountTable->insert($accountData);
            $existingUser = $accountTable->findByField('email', $oauthData['email'] ?? '');
        } else {
            $userId = $existingUser[$tableName][Config::getAccountColumn('id')];
            $this->account->updateOAuthData($userId, $oauthData['oauth_id'], $oauthData['provider']);
        }
        
        if (!$existingUser) {
            throw new \Exception('Failed to create or retrieve user account.');
        }
        
        $userId = $existingUser[$tableName][Config::getAccountColumn('id')];
        $this->session->set(Config::getSessionKey(), $userId);
        
        return true;
    }

    /**
     * Get registered token provider by type
     * 
     * @param string $type Provider type (e.g., 'jwt', 'api_key')
     * @return TokenProvider Token provider instance
     * @throws InvalidArgumentException If provider not registered
     */
    public function getTokenProvider(string $type): TokenProvider
    {
        return Config::getTokenProvider($type);
    }

    /**
     * Generate token for authenticated user
     * 
     * @param int $userId User ID
     * @param string $tokenType Token type (jwt, api_key)
     * @param array $claims Additional claims/metadata
     * @param int|null $expiresIn Token expiration in seconds
     * @return string Generated token
     * @throws InvalidArgumentException If token type not registered
     */
    public function generateToken(int $userId, string $tokenType, array $claims = [], ?int $expiresIn = null): string
    {
        $provider = $this->getTokenProvider($tokenType);
        return $provider->generateToken($userId, $claims, $expiresIn);
    }

    /**
     * Validate token and get token data
     * 
     * @param string $token Token to validate
     * @param string $tokenType Expected token type
     * @return array Token data
     * @throws \Exception If validation fails
     */
    public function validateToken(string $token, string $tokenType): array
    {
        $provider = $this->getTokenProvider($tokenType);
        return $provider->validateToken($token);
    }

    /**
     * Authenticate user with token
     * 
     * Validates token and sets session with user ID
     * 
     * @param string $token Token to validate
     * @param string $tokenType Token type
     * @return bool True if authentication successful
     * @throws \Exception If validation fails
     */
    public function authenticateWithToken(string $token, string $tokenType): bool
    {
        try {
            $tokenData = $this->validateToken($token, $tokenType);
            $userId = $tokenData['user_id'];
            $this->session->set(Config::getSessionKey(), $userId);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Revoke token
     * 
     * @param string $token Token to revoke
     * @param string $tokenType Token type
     * @return bool True if revocation successful
     */
    public function revokeToken(string $token, string $tokenType): bool
    {
        try {
            $provider = $this->getTokenProvider($tokenType);
            return $provider->revokeToken($token);
        } catch (\Exception $e) {
            return false;
        }
    }

}
