<?php

declare(strict_types=1);

namespace Fellowship\Push;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A Firebase service account, parsed from the JSON an admin pastes into
 * the settings screen.
 *
 * <b>`token_uri` is validated against an allow-list, not trusted.</b> It
 * arrives inside a JSON blob pasted by a human, and it is the address
 * this server signs an assertion to and posts credentials at. A doctored
 * file could otherwise redirect that to anywhere; anything but Google's
 * two published token endpoints falls back to the default rather than
 * being honoured.
 */
final class ServiceAccount
{
    private const TOKEN_ENDPOINTS = [
        'https://oauth2.googleapis.com/token',
        'https://accounts.google.com/o/oauth2/token',
    ];

    private function __construct(
        public readonly string $projectId,
        public readonly string $clientEmail,
        public readonly string $privateKey,
        public readonly string $tokenUri,
    ) {
    }

    public static function fromJson(string $json): ?self
    {
        $json = trim($json);
        if ($json === '') {
            return null;
        }

        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }

        $projectId   = self::string($data, 'project_id');
        $clientEmail = self::string($data, 'client_email');
        $privateKey  = self::string($data, 'private_key');

        if ($projectId === '' || $clientEmail === '' || $privateKey === '') {
            return null;
        }

        return new self($projectId, $clientEmail, $privateKey, self::tokenUri($data));
    }

    public function sendEndpoint(): string
    {
        return 'https://fcm.googleapis.com/v1/projects/' . rawurlencode($this->projectId) . '/messages:send';
    }

    /**
     * A short, stable identifier for this account, used to key the
     * cached access token. Not a secret and not reversible — it exists so
     * that replacing the service account invalidates the cache rather
     * than leaving a token for the old project in play.
     */
    public function fingerprint(): string
    {
        return substr(hash('sha256', $this->clientEmail . '|' . $this->projectId), 0, 16);
    }

    /** @param array<string, mixed> $data */
    private static function tokenUri(array $data): string
    {
        $default = self::TOKEN_ENDPOINTS[0];

        $configured = self::string($data, 'token_uri');
        if ($configured === '') {
            return $default;
        }

        $parts = parse_url($configured);
        if (!is_array($parts)) {
            return $default;
        }

        // Nothing that redirects the request or rides along with it.
        foreach (['user', 'pass', 'port', 'query', 'fragment'] as $unwanted) {
            if (isset($parts[$unwanted])) {
                return $default;
            }
        }

        if (strtolower((string) ($parts['scheme'] ?? '')) !== 'https') {
            return $default;
        }

        $normalised = 'https://'
            . strtolower((string) ($parts['host'] ?? ''))
            . (string) ($parts['path'] ?? '');

        return in_array($normalised, self::TOKEN_ENDPOINTS, true) ? $normalised : $default;
    }

    /** @param array<string, mixed> $data */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? '';
        return is_string($value) ? trim($value) : '';
    }
}
