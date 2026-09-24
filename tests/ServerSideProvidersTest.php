<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\VerifiedIdentity;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Auth\Providers\OAuthProvider;
use Fellowship\Core\Settings;

/**
 * The three browser-leg providers, from the callback inwards.
 *
 * <b>Each one exchanges a code and then decides whether to believe the
 * address in the token that comes back.</b> They differ in exactly one
 * respect that matters, and it is the respect a copy-paste between them
 * would destroy:
 *
 *  - <b>Google and Facebook require `email_verified`</b>, and reject an
 *    absent claim as firmly as a false one. OIDC mandates it; a token
 *    without it is non-compliant or doctored, and either way the address
 *    is not one to match a member against.
 *  - <b>Microsoft has no such claim on a consumer token</b>, so requiring
 *    it would refuse every sign-in. What stands in its place is the
 *    pinned issuer: on the MSA consumer tenant the address is one
 *    Microsoft verified, which is not true on the common endpoint where
 *    any tenant admin can mint a token asserting anything.
 *
 * Every test here mints a real RS256 token and serves a real JWKS, so
 * what is exercised is the provider's decision rather than a stubbed
 * answer about it.
 */

covers(\Fellowship\Auth\Providers\GoogleProvider::class, \Fellowship\Auth\Providers\MicrosoftProvider::class, \Fellowship\Auth\Providers\FacebookProvider::class);

const SERVER_SIDE_PROVIDERS_REDIRECT = 'https://aa-bristol.org/wp-json/fellowship/v1/auth/callback';

const SERVER_SIDE_PROVIDERS_NONCE = 'the-issued-nonce';

const SERVER_SIDE_PROVIDERS_KID = 'test-key-1';

beforeEach(function () {
    FakeWpHttp::reset();

    WpState::$options[Settings::OPTION_PUBLIC] = [
        'client_id_google' => 'google-client-id',
        'client_id_microsoft' => 'ms-client-id',
        'client_id_facebook' => 'fb-app-id',
    ];

    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $this->key = $key;
});

// ── Google ────────────────────────────────────────────────────────

test('Google accepts a verified address', function () {
    $identity = serverSideProvidersExchange(serverSideProvidersGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email_verified' => true,
    ]);

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
    expect($identity->provider)->toBe('google');
});

test('Google refuses an unverified address', function () {
    expect(serverSideProvidersExchange(serverSideProvidersGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email_verified' => false,
    ]))->toBeNull();
});

test('Google refuses a token with no verified claim at all', function () {
    // Absent is rejected as firmly as false: OIDC requires it, so a
    // token without one is non-compliant or doctored.
    expect(serverSideProvidersExchange(serverSideProvidersGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
    ], remove: ['email_verified']))->toBeNull();
});

test('Google lowers the address', function () {
    $identity = serverSideProvidersExchange(serverSideProvidersGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email' => 'Member@Example.ORG',
        'email_verified' => true,
    ]);

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
});

test('Google asks for nothing beyond an address', function () {
    $url = serverSideProvidersGoogle()->getAuthorizationUrl('state-1', SERVER_SIDE_PROVIDERS_NONCE, SERVER_SIDE_PROVIDERS_REDIRECT);

    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect($query['scope'] ?? null)->toBe('openid email');
    // A phone is often shared or carries several accounts, and
    // silently reusing whichever Google saw last would enrol the
    // wrong member.
    expect($query['prompt'] ?? null)->toBe('select_account');
});

// ── Microsoft ─────────────────────────────────────────────────────

test('Microsoft accepts a consumer token', function () {
    $identity = serverSideProvidersExchange(serverSideProvidersMicrosoft(), [
        'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
        'aud' => 'ms-client-id',
    ], remove: ['email_verified']);

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
});

test('Microsoft refuses a token from another tenant', function () {
    // The security property the pinned issuer exists for: on the
    // common endpoint any tenant admin can mint a token asserting any
    // address, which would be an impersonation route past the gate.
    expect(serverSideProvidersExchange(serverSideProvidersMicrosoft(), [
        'iss' => 'https://login.microsoftonline.com/some-other-tenant-guid/v2.0',
        'aud' => 'ms-client-id',
    ], remove: ['email_verified']))->toBeNull();
});

test('Microsoft falls back to preferred username', function () {
    // Consumer tokens often carry the address there rather than in
    // `email`.
    $identity = serverSideProvidersExchange(serverSideProvidersMicrosoft(), [
        'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
        'aud' => 'ms-client-id',
        'preferred_username' => 'member@example.org',
    ], remove: ['email', 'email_verified']);

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
});

test('Microsoft refuses a preferred username that is not an address', function () {
    // preferred_username is a display handle by specification, and
    // handing the member gate something that is not an address would
    // match nobody in a way nothing explains.
    expect(serverSideProvidersExchange(serverSideProvidersMicrosoft(), [
        'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
        'aud' => 'ms-client-id',
        'preferred_username' => 'DaveP',
    ], remove: ['email', 'email_verified']))->toBeNull();
});

// ── Facebook ──────────────────────────────────────────────────────

test('Facebook accepts a verified address', function () {
    $identity = serverSideProvidersExchange(serverSideProvidersFacebook(), [
        'iss' => 'https://www.facebook.com',
        'aud' => 'fb-app-id',
        'email_verified' => true,
    ], verifier: 'the-code-verifier');

    expect($identity)->not->toBeNull();
    expect($identity->provider)->toBe('facebook');
});

test('Facebook refuses an unverified address', function () {
    expect(serverSideProvidersExchange(serverSideProvidersFacebook(), [
        'iss' => 'https://www.facebook.com',
        'aud' => 'fb-app-id',
        'email_verified' => false,
    ], verifier: 'the-code-verifier'))->toBeNull();
});

test('Facebook sends the verifier on the exchange', function () {
    // Its token endpoint refuses an exchange whose authorise leg
    // carried a challenge without a matching verifier.
    serverSideProvidersExchange(serverSideProvidersFacebook(), [
        'iss' => 'https://www.facebook.com',
        'aud' => 'fb-app-id',
        'email_verified' => true,
    ], verifier: 'the-code-verifier');

    $sent = FakeWpHttp::sentArgs(0);
    expect($sent['body']['code_verifier'] ?? null)->toBe('the-code-verifier');
});

test('the client secret is sent in the body and never the URL', function () {
    // A secret in a request line lands in every proxy log, access log
    // and tracing span between here and the provider.
    serverSideProvidersExchange(serverSideProvidersGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email_verified' => true,
    ]);

    expect(FakeWpHttp::sentUrl(0))->not->toContain('client_secret');
    expect(FakeWpHttp::sentArgs(0)['body'])->toHaveKey('client_secret');
});

// ── What they all refuse ──────────────────────────────────────────

test('a token endpoint that answers no id token is refused', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.x"}');

    expect(serverSideProvidersGoogle()->handleCallback('a-code', SERVER_SIDE_PROVIDERS_NONCE, SERVER_SIDE_PROVIDERS_REDIRECT))->toBeNull();
});

test('a refused exchange is refused', function () {
    FakeWpHttp::pushResponse(400, '{"error":"invalid_grant"}');

    expect(serverSideProvidersGoogle()->handleCallback('a-code', SERVER_SIDE_PROVIDERS_NONCE, SERVER_SIDE_PROVIDERS_REDIRECT))->toBeNull();
});

test('an unreachable token endpoint is refused', function () {
    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

    expect(serverSideProvidersGoogle()->handleCallback('a-code', SERVER_SIDE_PROVIDERS_NONCE, SERVER_SIDE_PROVIDERS_REDIRECT))->toBeNull();
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * Run a provider's callback against a token it should be willing to
 * read, and answer the identity it made of it.
 *
 * @param array<string, mixed> $claims
 * @param list<string>         $remove
 */
function serverSideProvidersExchange(
    OAuthProvider $provider,
    array $claims,
    array $remove = [],
    ?string $verifier = null
): ?VerifiedIdentity {
    $token = serverSideProvidersToken($claims, $remove);

    // The token exchange, then the JWKS the verifier fetches.
    FakeWpHttp::pushResponse(200, (string) json_encode(['id_token' => $token]));
    FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [serverSideProvidersJwk()]]));

    return $provider->handleCallback('a-code', SERVER_SIDE_PROVIDERS_NONCE, SERVER_SIDE_PROVIDERS_REDIRECT, $verifier);
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function serverSideProvidersToken(array $overrides, array $remove): string
{
    $claims = array_merge([
        'sub' => 'sub-1',
        'email' => 'member@example.org',
        'email_verified' => true,
        'nonce' => SERVER_SIDE_PROVIDERS_NONCE,
        'iat' => time(),
        'exp' => time() + 600,
    ], $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    $header = serverSideProvidersBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => SERVER_SIDE_PROVIDERS_KID, 'typ' => 'JWT']));
    $payload = serverSideProvidersBase64Url((string) json_encode($claims));

    $signature = '';
    openssl_sign($header . '.' . $payload, $signature, test()->key, OPENSSL_ALGO_SHA256);

    return $header . '.' . $payload . '.' . serverSideProvidersBase64Url($signature);
}

/** @return array<string, string> */
function serverSideProvidersJwk(): array
{
    $details = openssl_pkey_get_details(test()->key);
    expect($details)->toBeArray();

    return [
        'kty' => 'RSA',
        'kid' => SERVER_SIDE_PROVIDERS_KID,
        'use' => 'sig',
        'alg' => 'RS256',
        'n' => serverSideProvidersBase64Url($details['rsa']['n']),
        'e' => serverSideProvidersBase64Url($details['rsa']['e']),
    ];
}

function serverSideProvidersBase64Url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function serverSideProvidersGoogle(): GoogleProvider
{
    return new GoogleProvider(new Settings(), new JwtVerifier());
}

function serverSideProvidersMicrosoft(): MicrosoftProvider
{
    return new MicrosoftProvider(new Settings(), new JwtVerifier());
}

function serverSideProvidersFacebook(): FacebookProvider
{
    return new FacebookProvider(new Settings(), new JwtVerifier());
}
