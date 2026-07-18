<?php

declare(strict_types=1);

namespace NimblePHP\Authorization\OAuth;

use InvalidArgumentException;

/** Converts GitHub API responses to the module's provider-data contract. */
final class GitHubIdentityNormalizer
{
    /**
     * @param array<string, mixed> $user
     * @param array<int, array<string, mixed>> $emails
     * @return array<string, mixed>
     */
    public function normalize(array $user, array $emails): array
    {
        if (!isset($user['id']) || !is_scalar($user['id'])) {
            throw new InvalidArgumentException('GitHub response does not contain a user subject');
        }

        $verifiedEmail = '';

        foreach ($emails as $emailData) {
            if (
                ($emailData['primary'] ?? false) === true
                && ($emailData['verified'] ?? false) === true
                && is_string($emailData['email'] ?? null)
                && filter_var($emailData['email'], FILTER_VALIDATE_EMAIL) !== false
            ) {
                $verifiedEmail = $emailData['email'];
                break;
            }
        }

        return [
            'oauth_id' => (string)$user['id'],
            'oauth_provider' => 'github',
            'username' => is_string($user['login'] ?? null) ? $user['login'] : '',
            'email' => $verifiedEmail,
            'email_verified' => $verifiedEmail !== '',
            'name' => is_string($user['name'] ?? null) ? $user['name'] : ($user['login'] ?? ''),
            'avatar' => is_string($user['avatar_url'] ?? null) ? $user['avatar_url'] : '',
            'profile_url' => is_string($user['html_url'] ?? null) ? $user['html_url'] : '',
        ];
    }
}
