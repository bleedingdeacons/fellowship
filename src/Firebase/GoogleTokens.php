<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\Base64Url;
use Fellowship\Core\UserAgent;
use Fellowship\Logger\HasLogger;
use Fellowship\Push\ServiceAccount;

/**
 * Google credentials for the service account Fellowship holds.
 *
 * Two kinds, from the same signed assertion: an access token for Google's own APIs
 * and an ID token to prove who is calling a Cloud Function. Both last an hour and
 * are kept in a transient for a little less, so a request doesn't pay for a token
 * exchange each time.
 */
final class GoogleTokens
{
    use Base64Url;
    use HasLogger;

    public const DATASTORE_SCOPE = 'https://www.googleapis.com/auth/datastore';

    private const TRANSIENT_PREFIX = 'fellowship_google_token_';

    /** Google's tokens last an hour; refresh a little early. */
    private const CACHE_SECONDS = 3300;

    private const ASSERTION_TTL = 3600;

    private const TIMEOUT_SECONDS = 10;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /** An access token for this scope, or '' when one can't be had. */
    public function accessToken(ServiceAccount $account, string $scope): string
    {
        return $this->token($account, ['scope' => $scope], 'access_token');
    }

    /** An ID token for this audience, or '' when one can't be had. */
    public function idToken(ServiceAccount $account, string $audience): string
    {
        return $this->token($account, ['target_audience' => $audience], 'id_token');
    }

    /** @param array<string, string> $purpose */
    private function token(ServiceAccount $account, array $purpose, string $field): string
    {
        $key = self::TRANSIENT_PREFIX . hash('sha256', $account->fingerprint() . '|' . implode('|', $purpose));

        $cached = get_transient($key);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $assertion = $this->assertion($account, $purpose);
        if ($assertion === '') {
            return '';
        }

        $response = wp_remote_post($account->tokenUri, [
            'timeout'    => self::TIMEOUT_SECONDS,
            'user-agent' => UserAgent::plugin(),
            'headers'    => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'body'       => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion'  => $assertion,
            ],
        ]);

        if (is_wp_error($response)) {
            self::logWarning('Google token request failed', ['error' => $response->get_error_message()]);

            return '';
        }

        $decoded = json_decode((string) wp_remote_retrieve_body($response), true);
        $token = is_array($decoded) ? ($decoded[$field] ?? null) : null;

        if (!is_string($token) || $token === '') {
            self::logWarning('Google token response had no token', [
                'status' => (int) wp_remote_retrieve_response_code($response),
                'field'  => $field,
            ]);

            return '';
        }

        set_transient($key, $token, self::CACHE_SECONDS);

        return $token;
    }

    /** @param array<string, string> $purpose */
    private function assertion(ServiceAccount $account, array $purpose): string
    {
        $now = time();

        $claims = [
            'iss' => $account->clientEmail,
            'sub' => $account->clientEmail,
            'aud' => $account->tokenUri,
            'iat' => $now,
            'exp' => $now + self::ASSERTION_TTL,
        ] + $purpose;

        $signingInput = $this->base64UrlEncode((string) wp_json_encode(['alg' => 'RS256', 'typ' => 'JWT']))
            . '.'
            . $this->base64UrlEncode((string) wp_json_encode($claims));

        $key = openssl_pkey_get_private($account->privateKey);
        if ($key === false) {
            self::logWarning('Service-account private key could not be read for a Google token');

            return '';
        }

        $signature = '';
        if (openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256) === false) {
            self::logWarning('Google assertion could not be signed');

            return '';
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }
}
