<?php

declare(strict_types=1);

namespace Fellowship\Push;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\Base64Url;
use Fellowship\Logger\HasLogger;

/**
 * Posts to FCM's HTTP v1 API, minting its own OAuth access token from the
 * service account.
 *
 * <b>401 and 403 are logged as errors, everything else as warnings, and
 * the distinction matters.</b> A 401 or 403 is almost never about the
 * handset: it means this server cannot send at all — the service account
 * lacks `cloudmessaging.messages.create`, the Cloud Messaging API is not
 * enabled, or the credentials are for a different project. That is every
 * message to every member failing, not one dead phone. Reach ran with
 * exactly that fault undetected for weeks because it was logged at
 * warning alongside the ordinary refusals it is nothing like.
 */
final class FcmClient
{
    use Base64Url;
    use HasLogger;

    private const TOKEN_TRANSIENT_PREFIX = 'fellowship_fcm_token_';

    /** Google's tokens last an hour; refresh a little early. */
    private const TOKEN_CACHE_SECONDS = 3300;

    private const ASSERTION_TTL = 3600;

    private const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

    private const TIMEOUT_SECONDS = 10;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * @param array<string, mixed> $message The `message` object, as the
     *        HTTP v1 API defines it — token, data, android, and so on.
     */
    public function send(ServiceAccount $account, array $message): bool
    {
        $token = $this->accessToken($account);
        if ($token === '') {
            return false;
        }

        $response = wp_remote_post($account->sendEndpoint(), [
            'timeout' => self::TIMEOUT_SECONDS,
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json; charset=utf-8',
            ],
            'body' => (string) wp_json_encode(['message' => $message]),
        ]);

        if (is_wp_error($response)) {
            self::logWarning('FCM send failed', ['error' => $response->get_error_message()]);
            return false;
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status >= 200 && $status < 300) {
            return true;
        }

        $body = substr((string) wp_remote_retrieve_body($response), 0, 500);

        if ($status === 401 || $status === 403) {
            self::logError(
                'FCM refused to send. This is a configuration fault, not a handset fault — '
                . 'no message can be pushed to anyone until it is fixed. Check that the service '
                . 'account has the Firebase Cloud Messaging API Admin role on the project and '
                . 'that the FCM API is enabled.',
                ['status' => $status, 'body' => $body],
            );

            return false;
        }

        // Everything else is about this one message: a dead registration
        // token, a malformed payload, a rate limit, a bad hour at Google.
        // Ordinary, survivable, and not worth more than a warning —
        // the handset will collect the message on its next poll.
        self::logWarning('FCM rejected a message', ['status' => $status, 'body' => $body]);

        return false;
    }

    private function accessToken(ServiceAccount $account): string
    {
        $key = self::TOKEN_TRANSIENT_PREFIX . $account->fingerprint();

        $cached = get_transient($key);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $assertion = $this->assertion($account);
        if ($assertion === '') {
            return '';
        }

        $response = wp_remote_post($account->tokenUri, [
            'timeout' => self::TIMEOUT_SECONDS,
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'body'    => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion'  => $assertion,
            ],
        ]);

        if (is_wp_error($response)) {
            self::logWarning('FCM token request failed', ['error' => $response->get_error_message()]);
            return '';
        }

        $decoded = json_decode((string) wp_remote_retrieve_body($response), true);
        if (!is_array($decoded) || !isset($decoded['access_token']) || !is_string($decoded['access_token'])) {
            self::logWarning('FCM token response had no access_token', [
                'status' => (int) wp_remote_retrieve_response_code($response),
            ]);
            return '';
        }

        $token = $decoded['access_token'];
        set_transient($key, $token, self::TOKEN_CACHE_SECONDS);

        return $token;
    }

    /** The signed JWT exchanged for an access token. */
    private function assertion(ServiceAccount $account): string
    {
        $now = time();

        $header = ['alg' => 'RS256', 'typ' => 'JWT'];
        $claims = [
            'iss'   => $account->clientEmail,
            'scope' => self::SCOPE,
            'aud'   => $account->tokenUri,
            'iat'   => $now,
            'exp'   => $now + self::ASSERTION_TTL,
        ];

        $signingInput = $this->base64UrlEncode((string) wp_json_encode($header))
            . '.'
            . $this->base64UrlEncode((string) wp_json_encode($claims));

        $key = openssl_pkey_get_private($account->privateKey);
        if ($key === false) {
            self::logWarning('FCM service-account private key could not be read');
            return '';
        }

        $signature = '';
        if (openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256) === false) {
            self::logWarning('FCM assertion could not be signed');
            return '';
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }
}
