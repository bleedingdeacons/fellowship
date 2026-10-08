<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;

/**
 * The floor under {@see JwtVerifier}'s cache-busting JWKS refetch.
 *
 * An unknown `kid` makes verify() retry with the cache busted, and that path
 * is reachable by anyone: the exchange route takes any Apple ID token, and
 * reading its header costs nothing. Without the floor, a token with a random
 * kid forced an outbound HTTPS call on every request. Reach had the floor;
 * this verifier, copied from Reach's before it gained one, did not.
 *
 * Deliberately built without openssl_pkey_new(). These assertions are about
 * how many times the key set is fetched, not about signatures — the kid
 * lookup comes before any signature check — so they run even where the RSA
 * tests skip for want of an openssl.cnf.
 */

const JWKS_FLOOR_URL = 'https://appleid.apple.com/auth/keys';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();
});

test('an unknown kid does not refetch the key set on every request', function () {
    jwksFloorServeKeySetWithout(40);

    $verifier = new JwtVerifier();
    for ($i = 0; $i < 20; $i++) {
        $verifier->verify(jwksFloorTokenWithKid('bogus-kid-' . $i), JWKS_FLOOR_URL, 'https://appleid.apple.com', 'org.aa-bristol.link');
    }

    // One fetch to populate the cache, and at most one cache-busting refetch
    // within the floor. Without the floor this was two per request, so 40.
    expect(FakeWpHttp::callCount())->toBeLessThanOrEqual(2);
});

test('the first unknown kid still gets one refetch', function () {
    // The floor throttles the refetch; it must not remove it. A genuine key
    // rotation is exactly this case, so the first miss has to reach Apple.
    jwksFloorServeKeySetWithout(2);

    (new JwtVerifier())->verify(jwksFloorTokenWithKid('rotated-in'), JWKS_FLOOR_URL, 'https://appleid.apple.com', 'org.aa-bristol.link');

    expect(FakeWpHttp::callCount())->toBe(2);
});

test('the floor is per key set not global', function () {
    // Apple's misses must not deny Google its refetch.
    $google = 'https://www.googleapis.com/oauth2/v3/certs';
    jwksFloorServeKeySetWithout(4);

    $verifier = new JwtVerifier();
    $verifier->verify(jwksFloorTokenWithKid('x'), JWKS_FLOOR_URL, 'https://appleid.apple.com', 'org.aa-bristol.link');
    $verifier->verify(jwksFloorTokenWithKid('x'), $google, 'https://accounts.google.com', 'google-client-id');

    $fetched = array_map(static fn (array $sent): string => $sent['url'], FakeWpHttp::$sent);

    expect(array_count_values($fetched))->toBe([JWKS_FLOOR_URL => 2, $google => 2]);
});

test('the floor outlives the verifier instance', function () {
    // The container builds a fresh verifier per request. The floor lives in a
    // transient, so the next request is held by it too.
    jwksFloorServeKeySetWithout(4);

    (new JwtVerifier())->verify(jwksFloorTokenWithKid('one'), JWKS_FLOOR_URL, 'https://appleid.apple.com', 'org.aa-bristol.link');
    (new JwtVerifier())->verify(jwksFloorTokenWithKid('two'), JWKS_FLOOR_URL, 'https://appleid.apple.com', 'org.aa-bristol.link');

    expect(FakeWpHttp::callCount())->toBe(2);
});

/**
 * A structurally valid RS256 token with the given kid and a nonsense
 * signature — the kid lookup comes before any signature check.
 */
function jwksFloorTokenWithKid(string $kid): string
{
    return jwksFloorEncode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])
        . '.' . jwksFloorEncode(['iss' => 'https://appleid.apple.com', 'aud' => 'org.aa-bristol.link', 'iat' => time(), 'exp' => time() + 3600])
        . '.' . rtrim(strtr(base64_encode('not-a-real-signature'), '+/', '-_'), '=');
}

/** Queue a key set that never holds the kid under test, so every lookup misses. */
function jwksFloorServeKeySetWithout(int $times): void
{
    for ($i = 0; $i < $times; $i++) {
        FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [[
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'a-kid-that-is-never-asked-for',
            'n'   => 'AQAB',
            'e'   => 'AQAB',
        ]]]));
    }
}

/** @param array<string, mixed> $data */
function jwksFloorEncode(array $data): string
{
    return rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');
}
