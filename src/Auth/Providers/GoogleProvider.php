<?php

declare(strict_types=1);

namespace Fellowship\Auth\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\Settings;

/**
 * Sign in with Google — the server-side code-exchange flow, and the
 * first one Link uses because Android is the first head.
 *
 * The handset opens the authorization URL in a system browser tab, the
 * browser comes back to this site's callback with a code, and this
 * server exchanges it. The client secret stays here; the handset only
 * ever sees a one-time code.
 */
final class GoogleProvider implements OAuthProvider
{
    public const PROVIDER_NAME = 'google';

    private const ISSUER = 'https://accounts.google.com';
    private const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';
    private const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

    public function __construct(
        private readonly Settings $settings,
        private readonly JwtVerifier $verifier,
    ) {
    }

    public function name(): string
    {
        return self::PROVIDER_NAME;
    }

    public function isServerSide(): bool
    {
        return true;
    }

    public function getAuthorizationUrl(string $state, string $nonce, string $redirectUri): string
    {
        $params = [
            'client_id'     => $this->settings->getClientId(self::PROVIDER_NAME),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            // Only what the gate needs. Fellowship never reads a mailbox,
            // a profile or a contact list, and asking for scopes it does
            // not use would be both a worse consent screen and a larger
            // token to lose.
            'scope'         => 'openid email',
            'state'         => $state,
            'nonce'         => $nonce,
            // A phone is often shared or has several accounts on it, and
            // silently reusing whichever Google saw last would enrol the
            // wrong member.
            'prompt'        => 'select_account',
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    public function handleCallback(string $code, string $nonce, string $redirectUri): ?VerifiedIdentity
    {
        $tokens = $this->exchangeCode($code, $redirectUri);
        if ($tokens === null || empty($tokens['id_token']) || !is_string($tokens['id_token'])) {
            return null;
        }

        $claims = $this->verifier->verify(
            $tokens['id_token'],
            self::JWKS_URL,
            self::ISSUER,
            $this->settings->getClientId(self::PROVIDER_NAME),
            $nonce,
        );

        if ($claims === null) {
            return null;
        }

        // The whole point of this flow is a verified email.
        if (empty($claims['email']) || !is_string($claims['email'])) {
            return null;
        }

        // Reject when the claim is missing as well as when it is false.
        // OIDC requires `email_verified`; a token without it is either
        // non-compliant or doctored, and either way the address is not
        // one to match a member against.
        if (($claims['email_verified'] ?? null) !== true) {
            return null;
        }

        return new VerifiedIdentity(
            strtolower($claims['email']),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        throw new \LogicException('Google uses the server-side flow; verifyIdToken does not apply.');
    }

    /**
     * @return array<string, mixed>|null
     */
    private function exchangeCode(string $code, string $redirectUri): ?array
    {
        $response = wp_remote_post(self::TOKEN_URL, [
            'timeout' => 10,
            'headers' => ['Accept' => 'application/json'],
            'body'    => [
                'code'          => $code,
                'client_id'     => $this->settings->getClientId(self::PROVIDER_NAME),
                'client_secret' => $this->settings->getClientSecret(self::PROVIDER_NAME),
                'redirect_uri'  => $redirectUri,
                'grant_type'    => 'authorization_code',
            ],
        ]);

        if (is_wp_error($response)) {
            return null;
        }

        $httpCode = (int) wp_remote_retrieve_response_code($response);
        if ($httpCode < 200 || $httpCode >= 300) {
            return null;
        }

        $decoded = json_decode((string) wp_remote_retrieve_body($response), true);
        return is_array($decoded) ? $decoded : null;
    }
}
