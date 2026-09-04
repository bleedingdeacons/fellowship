<?php

declare(strict_types=1);

namespace Fellowship\Auth\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\Base64Url;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\Settings;

/**
 * Facebook Login, through the OIDC authorisation-code flow with PKCE.
 *
 * Closer to Google than to Apple: a browser leg, a code this server
 * exchanges, an `id_token` verified against Facebook's JWKS. Three
 * differences are worth naming because each one has bitten somebody.
 *
 * <b>PKCE is mandatory here, and only here.</b> Facebook's token endpoint
 * refuses an exchange whose authorise leg carried a `code_challenge`
 * without a matching `code_verifier` — "No code_verifier specified when a
 * code challenge is provided". The client secret still travels too;
 * Facebook is a confidential client from this side and PKCE is layered on
 * top rather than replacing it. This is the sole reason
 * {@see \Fellowship\Auth\StateStore} carries a verifier at all.
 *
 * <b>The endpoints are versioned and live on two different hosts.</b>
 * Authorise on www.facebook.com, token on graph.facebook.com, both under
 * a required version segment. Bumping v21 is a one-line change here when
 * Facebook deprecates it.
 *
 * <b>POST for the exchange, not GET.</b> Facebook accepts either, but a
 * GET puts the client secret in a request line — and therefore in every
 * proxy log, access log and tracing span between here and Menlo Park.
 *
 * Scopes are `openid email`, the same as Google, and deliberately not
 * `public_profile`: the point of the flow is a verified address, not a
 * profile this plugin has nowhere to put.
 */
final class FacebookProvider implements OAuthProvider
{
    use Base64Url;

    public const PROVIDER_NAME = 'facebook';

    private const ISSUER = 'https://www.facebook.com';
    private const AUTH_URL = 'https://www.facebook.com/v21.0/dialog/oauth';
    private const TOKEN_URL = 'https://graph.facebook.com/v21.0/oauth/access_token';
    private const JWKS_URL = 'https://www.facebook.com/.well-known/oauth/openid/jwks/';

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

    public function requiresPkce(): bool
    {
        return true;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        if ($codeVerifier === null || $codeVerifier === '') {
            // The controller mints one for any provider that says it
            // requires PKCE, so arriving here without a verifier is a
            // wiring fault. Throwing beats building a URL whose exchange
            // is guaranteed to fail two steps later with an error message
            // that names neither this method nor that omission.
            throw new \LogicException('Facebook requires a PKCE code verifier.');
        }

        $params = [
            'client_id'             => $this->settings->getClientId(self::PROVIDER_NAME),
            'redirect_uri'          => $redirectUri,
            'response_type'         => 'code',
            'scope'                 => 'openid email',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $this->codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        if ($codeVerifier === null || $codeVerifier === '') {
            // Null rather than the exception the authorise leg throws:
            // by here the state has been consumed and a browser is
            // waiting, so this has to become a redirect with an error
            // rather than a 500.
            return null;
        }

        $tokens = $this->exchangeCode($code, $redirectUri, $codeVerifier);
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

        if (empty($claims['email']) || !is_string($claims['email'])) {
            return null;
        }

        // Absent is rejected as firmly as false. OIDC requires the claim;
        // a token without it is non-compliant or doctored, and either way
        // the address is not one to match a member against.
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
        throw new \LogicException('Facebook uses the server-side flow; verifyIdToken does not apply.');
    }

    /**
     * @return array<string, mixed>|null
     */
    private function exchangeCode(string $code, string $redirectUri, string $codeVerifier): ?array
    {
        $response = wp_remote_post(self::TOKEN_URL, [
            'timeout' => 10,
            'headers' => [
                'Accept'       => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'client_id'     => $this->settings->getClientId(self::PROVIDER_NAME),
                'client_secret' => $this->settings->getClientSecret(self::PROVIDER_NAME),
                'redirect_uri'  => $redirectUri,
                'code'          => $code,
                'code_verifier' => $codeVerifier,
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

    /**
     * The S256 challenge from RFC 7636: base64url of the SHA-256 of the
     * verifier, unpadded.
     */
    private function codeChallenge(string $verifier): string
    {
        return $this->base64UrlEncode(hash('sha256', $verifier, true));
    }
}
