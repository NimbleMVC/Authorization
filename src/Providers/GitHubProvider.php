<?php

namespace NimblePHP\Authorization\Providers;

use NimblePHP\Authorization\Interfaces\OAuthProvider;

/**
 * GitHub OAuth2 provider
 *
 * Implements OAuth2 authentication flow for GitHub.
 * Requires client ID and client secret from GitHub app.
 *
 * Setup: https://github.com/settings/developers
 */
class GitHubProvider implements OAuthProvider
{
    private const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
    private const TOKEN_URL = 'https://github.com/login/oauth/access_token';
    private const USER_API_URL = 'https://api.github.com/user';
    private const USER_EMAIL_API_URL = 'https://api.github.com/user/emails';

    private string $clientId;
    private string $clientSecret;
    private string $name = 'github';

    /**
     * Create a new GitHubProvider
     *
     * @param string $clientId GitHub app client ID
     * @param string $clientSecret GitHub app client secret
     */
    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Get authorization URL
     *
     * @param string $redirectUri Callback URL
     * @param array $scopes Optional scopes (default: user:email)
     * @return string Authorization URL
     */
    public function getAuthorizationUrl(string $redirectUri, array $scopes = []): string
    {
        if (empty($scopes)) {
            $scopes = ['user:email'];
        }

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $this->generateState(),
        ];

        return self::AUTHORIZE_URL . '?' . http_build_query($params);
    }

    /**
     * Exchange code for access token
     *
     * @param string $code Authorization code
     * @param string $redirectUri Callback URL
     * @return string Access token
     * @throws \Exception If exchange fails
     */
    public function exchangeCodeForToken(string $code, string $redirectUri): string
    {
        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ];

        $response = $this->makeRequest('POST', self::TOKEN_URL, $params);

        if (!isset($response['access_token'])) {
            throw new \Exception('Failed to get access token: ' . ($response['error'] ?? 'Unknown error'));
        }

        return $response['access_token'];
    }

    /**
     * Get user data from GitHub
     *
     * @param string $accessToken Access token
     * @return array User data
     * @throws \Exception If retrieval fails
     */
    public function getUserData(string $accessToken): array
    {
        $user = $this->makeAuthenticatedRequest('GET', self::USER_API_URL, $accessToken);

        $result = [
            'oauth_id' => (string)$user['id'],
            'oauth_provider' => $this->name,
            'username' => $user['login'] ?? '',
            'email' => $user['email'] ?? '',
            'name' => $user['name'] ?? $user['login'] ?? '',
            'avatar' => $user['avatar_url'] ?? '',
            'profile_url' => $user['html_url'] ?? '',
        ];

        if (empty($result['email'])) {
            $emails = $this->getEmails($accessToken);
            foreach ($emails as $emailData) {
                if ($emailData['primary']) {
                    $result['email'] = $emailData['email'];
                    break;
                }
            }
        }

        return $result;
    }

    /**
     * Get provider name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get client ID
     *
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Get client secret
     *
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * Get user emails from GitHub
     *
     * @param string $accessToken Access token
     * @return array List of emails
     */
    private function getEmails(string $accessToken): array
    {
        try {
            return $this->makeAuthenticatedRequest('GET', self::USER_EMAIL_API_URL, $accessToken);
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Make HTTP request to GitHub API
     *
     * @param string $method HTTP method
     * @param string $url API URL
     * @param array $data Request data
     * @return array Response data
     * @throws \Exception If request fails
     */
    private function makeRequest(string $method, string $url, array $data = []): array
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new \Exception('HTTP request failed: ' . $error);
        }

        $data = json_decode($response, true);

        if ($httpCode >= 400) {
            throw new \Exception('GitHub API error: ' . ($data['message'] ?? 'Unknown error'));
        }

        return $data ?? [];
    }

    /**
     * Make authenticated HTTP request
     *
     * @param string $method HTTP method
     * @param string $url API URL
     * @param string $accessToken Access token
     * @return array Response data
     * @throws \Exception If request fails
     */
    private function makeAuthenticatedRequest(string $method, string $url, string $accessToken): array
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Authorization: token ' . $accessToken,
            'User-Agent: NimblePHP-Authorization'
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new \Exception('HTTP request failed: ' . $error);
        }

        $data = json_decode($response, true);

        if ($httpCode >= 400) {
            throw new \Exception('GitHub API error: ' . ($data['message'] ?? 'Unknown error'));
        }

        return $data ?? [];
    }

    /**
     * Generate state parameter for security
     *
     * @return string
     */
    private function generateState(): string
    {
        return bin2hex(random_bytes(16));
    }
}
