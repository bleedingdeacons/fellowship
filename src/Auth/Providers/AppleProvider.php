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
 * Sign in with Apple — the client-side flow.
 *
 * iOS hands the app a signed ID token from its own system sheet, so
 * there is no browser leg, no authorization code and no client secret in
 * play. The app posts the token here and this verifies it against
 * Apple's JWKS exactly as the Google path verifies the one it fetched
 * itself. The verification is the same; only who did the fetching
 * differs, which is why the check that matters lives in
 * {@see JwtVerifier} rather than in either provider.
 *
 * <b>Private Relay addresses are accepted.</b> Apple lets a user hide
 * behind an `@privaterelay.appleid.com` forwarding address, and one of
 * those will simply not match a Unity member — the gate will refuse it
 * and the member will be told to sign in with the address the intergroup
 * holds. That is the correct outcome and needs no special case here;
 * Reach carries an AnonymisedEmailDetector to say something kinder about
 * it, which is worth porting if this turns into a support burden.
 */
final class AppleProvider implements OAuthProvider
{
    public const PROVIDER_NAME = 'apple';

    private const ISSUER = 'https://appleid.apple.com';
    private const JWKS_URL = 'https://appleid.apple.com/auth/keys';

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
        return false;
    }

    public function getAuthorizationUrl(string $state, string $nonce, string $redirectUri): string
    {
        throw new \LogicException('Apple uses the client-side flow; getAuthorizationUrl does not apply.');
    }

    public function handleCallback(string $code, string $nonce, string $redirectUri): ?VerifiedIdentity
    {
        throw new \LogicException('Apple uses the client-side flow; handleCallback does not apply.');
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        $claims = $this->verifier->verify(
            $idToken,
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

        // Apple sets email_verified for every address it issues, private
        // relay included. The claim may be a bool or the string "true"
        // depending on the token surface; an absent claim is rejected.
        $verified = $claims['email_verified'] ?? null;
        if ($verified !== true && $verified !== 'true') {
            return null;
        }

        return new VerifiedIdentity(
            strtolower($claims['email']),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }
}
