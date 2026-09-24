<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Core\Settings;
use WP_Error;

/**
 * Every way an identity token is refused.
 *
 * <b>A verifier is only as good as its refusals.</b> The happy path is
 * one branch and the rest of the method is the security: an unsigned
 * token, a token signed with a key nobody published, a token for another
 * application, a token whose nonce belongs to a different sign-in. Each
 * of those is somebody's attempt, and each has to answer null rather
 * than throwing — a throw here becomes a 500 on the callback leg, which
 * tells the caller their guess was interesting.
 *
 * <b>Facebook is the one provider that requires PKCE.</b> Its callback
 * refuses a missing verifier with null rather than the exception the
 * authorise leg throws, because by that point the state has been
 * consumed and a browser is waiting — the only thing that can be done
 * with it is a redirect carrying an error.
 */

covers(\Fellowship\Auth\JwtVerifier::class, \Fellowship\Auth\Providers\FacebookProvider::class);

const TOKEN_REFUSAL_JWKS = 'https://example.org/jwks';

const TOKEN_REFUSAL_ISSUER = 'https://example.org';

const TOKEN_REFUSAL_AUDIENCE = 'a-client-id';

beforeEach(function () {
    FakeWpHttp::reset();
});

// ── The verifier ──────────────────────────────────────────────────

test('something without three parts is not a token', function () {
    expect(tokenRefusalVerify('not-a-token'))->toBeNull();
    expect(tokenRefusalVerify('two.parts'))->toBeNull();
});

test('a header that is not JSON is refused', function () {
    // Refused on shape before anything is fetched, so a malformed
    // token costs no round trip to the provider.
    expect(tokenRefusalVerify(tokenRefusalToken('~~~', '~~~', 'sig')))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('a token signing itself with no algorithm is refused', function () {
    // "alg": "none" is the oldest trick there is, and HMAC is the
    // second oldest — a verifier that accepted HS256 would verify
    // tokens against the provider's own public key as the secret.
    foreach (['none', 'HS256'] as $alg) {
        expect(tokenRefusalVerify(signedShape(['alg' => $alg, 'kid' => 'k1'])))->toBeNull($alg . ' was accepted.');
    }
});

test('a token naming no key is refused', function () {
    // Without a kid there is nothing to look up, and picking a key
    // by guessing would defeat rotation.
    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256'])))->toBeNull();
    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256', 'kid' => ''])))->toBeNull();
});

test('a key set that cannot be fetched refuses rather than throws', function () {
    FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));
    FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));

    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256', 'kid' => 'k1'])))->toBeNull();
});

test('a key set that is not a key set is refused', function () {
    FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');
    FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');

    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256', 'kid' => 'k1'])))->toBeNull();
});

test('a key that is not an RSA key is refused', function () {
    // The DER is hand-rolled for RSA only; handing it an EC key
    // would build a PEM that nothing can verify against.
    $jwks = (string) wp_json_encode(['keys' => [['kid' => 'k1', 'kty' => 'EC', 'n' => 'aaa', 'e' => 'AQAB']]]);

    FakeWpHttp::pushResponse(200, $jwks);
    FakeWpHttp::pushResponse(200, $jwks);

    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256', 'kid' => 'k1'])))->toBeNull();
});

test('an RSA key missing its modulus is refused', function () {
    $jwks = (string) wp_json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA', 'n' => '', 'e' => '']]]);

    FakeWpHttp::pushResponse(200, $jwks);
    FakeWpHttp::pushResponse(200, $jwks);

    expect(tokenRefusalVerify(signedShape(['alg' => 'RS256', 'kid' => 'k1'])))->toBeNull();
});

// ── Facebook ──────────────────────────────────────────────────────

test('Facebook names itself and demands PKCE', function () {
    // The registry keys on the name, and the state store only keeps
    // a verifier for a provider that says it needs one.
    $provider = tokenRefusalFacebook();

    expect($provider->name())->toBe('facebook');
    expect($provider->requiresPkce())->toBeTrue();
});

test('a callback with no verifier is refused rather than thrown', function () {
    // By here the state is consumed and a browser is waiting, so
    // this has to become a redirect with an error rather than a 500.
    expect(tokenRefusalFacebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', null))->toBeNull();
    expect(tokenRefusalFacebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', ''))->toBeNull();
});

test('a code exchange that fails is refused', function () {
    FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));

    expect(tokenRefusalFacebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'))->toBeNull();
});

test('an exchange that answers no id token is refused', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"an-access-token"}');

    expect(tokenRefusalFacebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'))->toBeNull();
});

test('an exchange refused by Facebook is refused here', function () {
    FakeWpHttp::pushResponse(400, '{"error":{"message":"bad code"}}');

    expect(tokenRefusalFacebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'))->toBeNull();
});

// ── Fixtures ──────────────────────────────────────────────────────

function tokenRefusalFacebook(): FacebookProvider
{
    $settings = new Settings();
    $settings->setClientId('facebook', TOKEN_REFUSAL_AUDIENCE);
    $settings->setClientSecret('facebook', 'a-client-secret');

    return new FacebookProvider($settings, new JwtVerifier());
}

/** @return array<string, mixed>|null */
function tokenRefusalVerify(string $jwt): ?array
{
    return (new JwtVerifier())->verify($jwt, TOKEN_REFUSAL_JWKS, TOKEN_REFUSAL_ISSUER, TOKEN_REFUSAL_AUDIENCE);
}

/** @param array<string, mixed> $header */
function signedShape(array $header): string
{
    return tokenRefusalToken(
        (string) wp_json_encode($header),
        (string) wp_json_encode(['iss' => TOKEN_REFUSAL_ISSUER, 'aud' => TOKEN_REFUSAL_AUDIENCE, 'email' => 'dave@example.org']),
        'a-signature',
    );
}

function tokenRefusalToken(string $header, string $payload, string $signature): string
{
    return implode('.', array_map(
        static fn(string $part): string => rtrim(strtr(base64_encode($part), '+/', '-_'), '='),
        [$header, $payload, $signature],
    ));
}
