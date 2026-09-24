<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;

/**
 * The code that decides whether a stranger's claim about their own email
 * address is true.
 *
 * <b>Untested until now, which is the wrong shape of gap.</b> Everything
 * downstream of this class — the member gate, the device row, every
 * message ever sealed to the handset — rests on it refusing a token it
 * should refuse. A verifier that accepted `alg: none` would hand an
 * enrolment to anybody who could type an email address, and nothing else
 * in the plugin would notice.
 *
 * So the tests forge. Each one mints a real RS256 token with a real
 * keypair, serves a real JWKS through the fake HTTP transport, and then
 * breaks exactly one thing. The positive case exists to prove the
 * negatives are failing for the reason claimed rather than because the
 * fixture never worked.
 *
 * Keypairs are generated per test rather than committed — a fixture here
 * would mean a private key in a public repository.
 */

const JWT_VERIFIER_ISSUER = 'https://appleid.apple.com';

const JWT_VERIFIER_JWKS_URL = 'https://appleid.apple.com/auth/keys';

const JWT_VERIFIER_AUDIENCE = 'org.aa-bristol.link';

const JWT_VERIFIER_KID = 'test-key-1';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($key === false) {
        // The OPENSSL_CONF trap: without a usable openssl.cnf every
        // assertion below would be about the environment rather than
        // the verifier. Said plainly, because a silent skip here would
        // report a green suite that tested nothing.
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $this->key = $key;
});

test('a well formed token verifies', function () {
    serveJwks();

    $claims = jwtVerifierVerify(jwtVerifierToken());

    expect($claims)->toBeArray();
    expect($claims['email'])->toBe('member@example.org');
    expect($claims['sub'])->toBe('000123.abc.456');
});

test('an unsigned token is rejected', function () {
    // The textbook forgery: claim no algorithm and hope the verifier
    // takes the payload's word for itself.
    serveJwks();

    $header = jwtVerifierEncode(['alg' => 'none', 'kid' => JWT_VERIFIER_KID, 'typ' => 'JWT']);
    $payload = jwtVerifierEncode(jwtVerifierClaims());

    expect(jwtVerifierVerify($header . '.' . $payload . '.'))->toBeNull();
});

test('an hmac signed token is rejected', function () {
    // The subtler forgery: HS256 signed with the public key, which is
    // published and therefore known to everybody. A verifier that
    // dispatched on the header's alg would accept it.
    serveJwks();

    $header = jwtVerifierEncode(['alg' => 'HS256', 'kid' => JWT_VERIFIER_KID, 'typ' => 'JWT']);
    $payload = jwtVerifierEncode(jwtVerifierClaims());
    $signature = jwtVerifierBase64Url(
        hash_hmac('sha256', $header . '.' . $payload, publicKeyPem(), true)
    );

    expect(jwtVerifierVerify($header . '.' . $payload . '.' . $signature))->toBeNull();
});

test('a token signed by the wrong key is rejected', function () {
    serveJwks();

    $other = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    expect($other)->not->toBeFalse();

    expect(jwtVerifierVerify(jwtVerifierToken(signWith: $other)))->toBeNull();
});

test('a token for another audience is rejected', function () {
    // What stops a token minted for somebody else's app being replayed
    // at this one.
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(['aud' => 'com.example.someone-else'])))->toBeNull();
});

test('a token from another issuer is rejected', function () {
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(['iss' => 'https://accounts.google.com'])))->toBeNull();
});

test('a replayed nonce is rejected', function () {
    // What stops a token minted for this app being used twice.
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(['nonce' => 'a-different-nonce'])))->toBeNull();
});

test('an expired token is rejected', function () {
    serveJwks();

    // Well past the 60-second skew allowance.
    expect(jwtVerifierVerify(jwtVerifierToken(['exp' => time() - 3600])))->toBeNull();
});

test('a token issued in the future is rejected', function () {
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(['iat' => time() + 3600])))->toBeNull();
});

test('a token with no expiry is rejected', function () {
    // Would otherwise verify forever.
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(remove: ['exp'])))->toBeNull();
});

test('a token with no issued at is rejected', function () {
    serveJwks();

    expect(jwtVerifierVerify(jwtVerifierToken(remove: ['iat'])))->toBeNull();
});

test('an unknown key id is retried once then rejected', function () {
    // A provider that has just rotated leaves the cached JWKS without
    // the new kid. The verifier busts the cache and refetches once
    // rather than failing every sign-in for the cache's whole hour --
    // so two fetches, then a refusal.
    serveJwks();
    serveJwks();

    $header = jwtVerifierEncode(['alg' => 'RS256', 'kid' => 'a-kid-nobody-published', 'typ' => 'JWT']);
    $payload = jwtVerifierEncode(jwtVerifierClaims());
    $signature = jwtVerifierSign($header . '.' . $payload, $this->key);

    expect(jwtVerifierVerify($header . '.' . $payload . '.' . $signature))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('a freshly rotated key is found on the second fetch', function () {
    // The other half of the same behaviour, and the reason it exists:
    // the retry has to actually succeed when the key really is new.
    // Cached JWKS first, holding a kid this token was not signed with;
    // the refetch then carries the right one.
    WpState::$transients['fellowship_jwks_' . md5(JWT_VERIFIER_JWKS_URL)] = [
        'keys' => [jwtVerifierJwk('a-stale-kid')],
    ];

    serveJwks();

    $claims = jwtVerifierVerify(jwtVerifierToken());

    expect($claims)->toBeArray();
    expect(FakeWpHttp::callCount())->toBe(1);
});

test('a malformed token is rejected', function () {
    expect(jwtVerifierVerify('not-a-jwt'))->toBeNull();
    expect(jwtVerifierVerify('only.two'))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0, 'A malformed token must not cost a JWKS fetch.');
});

test('a JWKS that cannot be fetched is rejected', function () {
    FakeWpHttp::pushResponse(500, 'upstream is having a day');

    expect(jwtVerifierVerify(jwtVerifierToken()))->toBeNull();
});

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 * @param resource|\OpenSSLAsymmetricKey|null $signWith
 */
function jwtVerifierToken(array $overrides = [], array $remove = [], $signWith = null): string
{
    $claims = array_merge(jwtVerifierClaims(), $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    $header = jwtVerifierEncode(['alg' => 'RS256', 'kid' => JWT_VERIFIER_KID, 'typ' => 'JWT']);
    $payload = jwtVerifierEncode($claims);

    return $header . '.' . $payload . '.' . jwtVerifierSign($header . '.' . $payload, $signWith ?? test()->key);
}

/**
 * @return array<string, mixed>
 */
function jwtVerifierClaims(): array
{
    return [
        'iss'            => JWT_VERIFIER_ISSUER,
        'aud'            => JWT_VERIFIER_AUDIENCE,
        'sub'            => '000123.abc.456',
        'email'          => 'member@example.org',
        'email_verified' => 'true',
        'nonce'          => 'the-issued-nonce',
        'iat'            => time(),
        'exp'            => time() + 600,
    ];
}

/**
 * @return array<string, mixed>|null
 */
function jwtVerifierVerify(string $jwt): ?array
{
    return (new JwtVerifier())->verify(
        $jwt,
        JWT_VERIFIER_JWKS_URL,
        JWT_VERIFIER_ISSUER,
        JWT_VERIFIER_AUDIENCE,
        'the-issued-nonce',
    );
}

function serveJwks(): void
{
    FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [jwtVerifierJwk(JWT_VERIFIER_KID)]]));
}

/**
 * The public half, as a JWK.
 *
 * @return array<string, string>
 */
function jwtVerifierJwk(string $kid): array
{
    $details = openssl_pkey_get_details(test()->key);
    expect($details)->toBeArray();

    return [
        'kty' => 'RSA',
        'kid' => $kid,
        'use' => 'sig',
        'alg' => 'RS256',
        'n'   => jwtVerifierBase64Url($details['rsa']['n']),
        'e'   => jwtVerifierBase64Url($details['rsa']['e']),
    ];
}

function publicKeyPem(): string
{
    $details = openssl_pkey_get_details(test()->key);
    expect($details)->toBeArray();

    return (string) $details['key'];
}

/**
 * @param resource|\OpenSSLAsymmetricKey $key
 */
function jwtVerifierSign(string $input, $key): string
{
    $signature = '';
    openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);

    return jwtVerifierBase64Url($signature);
}

/**
 * @param array<string, mixed> $data
 */
function jwtVerifierEncode(array $data): string
{
    return jwtVerifierBase64Url((string) json_encode($data));
}

function jwtVerifierBase64Url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
