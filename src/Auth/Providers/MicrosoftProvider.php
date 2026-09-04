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
 * Microsoft sign-in via the Entra v2.0 endpoint, consumers tenant.
 *
 * Structurally Google's twin — a browser leg, a code this server
 * exchanges, an ID token verified against a JWKS — with two differences
 * that matter.
 *
 * <b>The `consumers` tenant, not `common`.</b> That accepts only personal
 * Microsoft accounts (Outlook.com, Hotmail, Live) and no work or school
 * ones, which is what an intergroup's members actually have. The Entra
 * app registration must match: "Personal Microsoft accounts only".
 *
 * <b>Which is what makes the issuer pinnable, and the email trustworthy.</b>
 * On `common` the `iss` claim carries the signing tenant's own GUID, so it
 * cannot be checked against a constant — and worse, any tenant admin can
 * mint a token asserting any address they like, so matching a member by
 * email there would be an impersonation route. The consumer tenant is a
 * single well-known GUID, pinned below, and an address in a token from it
 * is one Microsoft verified the holder controls.
 */
final class MicrosoftProvider implements OAuthProvider
{
    public const PROVIDER_NAME = 'microsoft';

    private const AUTH_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize';
    private const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
    private const JWKS_URL = 'https://login.microsoftonline.com/consumers/discovery/v2.0/keys';

    /** The MSA consumer tenant: fixed and well-known, not per-tenant. */
    private const ISSUER = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';

    private const SCOPE = 'openid email profile';

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
        return false;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        $params = [
            'client_id'     => $this->settings->getClientId(self::PROVIDER_NAME),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'response_mode' => 'query',
            // `profile` is here where Google needs only `openid email`,
            // because Microsoft will not populate preferred_username
            // without it — and that is the fallback the email is read
            // from below.
            'scope'         => self::SCOPE,
            'state'         => $state,
            'nonce'         => $nonce,
            'prompt'        => 'select_account',
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
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

        $email = $this->emailFrom($claims);
        if ($email === '') {
            return null;
        }

        // Deliberately no email_verified check, unlike Google and Apple.
        // Microsoft does not issue the claim on consumer tokens at all, so
        // requiring it would refuse every sign-in. What stands in its place
        // is the pinned issuer above: on the consumer tenant the address is
        // one Microsoft has verified, and that guarantee is why this
        // provider may only ever talk to that tenant.
        return new VerifiedIdentity(
            strtolower($email),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        throw new \LogicException('Microsoft uses the server-side flow; verifyIdToken does not apply.');
    }

    /**
     * The address, from `email` or the `preferred_username` fallback.
     *
     * <b>The fallback is checked for being an address at all.</b>
     * preferred_username is a display handle by specification and is not
     * promised to be an email; on the consumer tenant it almost always is
     * one, but taking it on trust would hand the member gate something
     * that is not an address and cannot match anybody.
     *
     * @param array<string, mixed> $claims
     */
    private function emailFrom(array $claims): string
    {
        if (!empty($claims['email']) && is_string($claims['email'])) {
            return $claims['email'];
        }

        $username = $claims['preferred_username'] ?? null;
        if (is_string($username) && $username !== '' && is_email($username)) {
            return $username;
        }

        return '';
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
                'client_id'     => $this->settings->getClientId(self::PROVIDER_NAME),
                'client_secret' => $this->settings->getClientSecret(self::PROVIDER_NAME),
                'code'          => $code,
                'redirect_uri'  => $redirectUri,
                'grant_type'    => 'authorization_code',
                'scope'         => self::SCOPE,
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
