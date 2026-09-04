<?php

declare(strict_types=1);

namespace Fellowship\Auth\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\VerifiedIdentity;

/**
 * One identity provider Link can sign in through.
 *
 * <b>Two flows, and {@see isServerSide()} says which.</b> Google on
 * Android hands the app an authorization code through the system
 * browser, which the server exchanges for an ID token — the client
 * secret never reaches the handset. Apple on iOS is different: the
 * platform's own Sign in with Apple sheet hands the app a signed ID
 * token directly, and there is no browser leg and no code to exchange.
 *
 * Calling the wrong half throws rather than returning null. A provider
 * asked for an authorization URL it does not have is a wiring mistake in
 * this plugin, not a failed sign-in, and it should be loud in
 * development rather than quietly answering "no" in production.
 *
 * <b>`$codeVerifier` is optional because only Facebook needs it.</b> It
 * is defaulted rather than added to a second interface: one provider
 * requiring PKCE does not justify splitting the contract every other
 * provider satisfies, and a null a provider ignores costs nothing.
 * {@see \Fellowship\Auth\StateStore} is what carries it between the
 * two legs.
 */
interface OAuthProvider
{
    public function name(): string;

    /** True for the code-exchange flow, false for a client-supplied ID token. */
    public function isServerSide(): bool;

    /** True when this provider's token endpoint requires PKCE. */
    public function requiresPkce(): bool;

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string;

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity;

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity;
}
