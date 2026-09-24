<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\VerifiedIdentity;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\AppleProvider;
use Fellowship\Core\Settings;

/**
 * Sign in with Apple, from the token inwards.
 *
 * <b>The provider is thin on purpose and that is exactly why it needs
 * testing.</b> Everything hard lives in {@see JwtVerifier}, so what is
 * left here is a short list of decisions about the claims — and a short
 * list of decisions is where a wrong one hides best. Accepting an
 * unverified address, or forgetting to lower-case one, would produce a
 * member gate that matches the wrong person or nobody at all, in a way
 * that looks like a data problem rather than a code one.
 *
 * A real verifier rather than a stub, because the two are only correct
 * together: substituting a permissive double here would test that the
 * provider reads claims out of an array.
 */

const APPLE_PROVIDER_ISSUER = 'https://appleid.apple.com';

const APPLE_PROVIDER_AUDIENCE = 'org.aa-bristol.link';

const APPLE_PROVIDER_NONCE = 'the-issued-nonce';

const APPLE_PROVIDER_KID = 'apple-key-1';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    WpState::$options[Settings::OPTION_PUBLIC] = ['client_id_apple' => APPLE_PROVIDER_AUDIENCE];

    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $this->key = $key;
});

test('a valid token yields the verified identity', function () {
    $identity = appleProviderVerify(appleProviderToken());

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
    expect($identity->provider)->toBe('apple');
    expect($identity->sub)->toBe('000123.abc.456');
});

test('the email is lower cased', function () {
    // Apple will return whatever case the address was registered in.
    // Unity's members are matched on the address, so a capital letter
    // arriving here would be a member who cannot sign in and no
    // explanation on either side.
    $identity = appleProviderVerify(appleProviderToken(['email' => 'Member@Example.ORG']));

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('member@example.org');
});

test('an unverified email is refused', function () {
    expect(appleProviderVerify(appleProviderToken(['email_verified' => 'false'])))->toBeNull();
    expect(appleProviderVerify(appleProviderToken(['email_verified' => false])))->toBeNull();
});

test('a missing email verified claim is refused', function () {
    // Absent is not the same as false, and is treated the same way:
    // the claim is the only evidence the address belongs to whoever
    // is holding the phone.
    expect(appleProviderVerify(appleProviderToken(remove: ['email_verified'])))->toBeNull();
});

test('a boolean true is accepted as well as the string', function () {
    // Apple has shipped this claim as both a JSON boolean and the
    // string "true" depending on the token surface. Accepting only one
    // of them would work until it silently did not.
    $identity = appleProviderVerify(appleProviderToken(['email_verified' => true]));

    expect($identity)->not->toBeNull();
});

test('a token with no email is refused', function () {
    expect(appleProviderVerify(appleProviderToken(remove: ['email'])))->toBeNull();
    expect(appleProviderVerify(appleProviderToken(['email' => ''])))->toBeNull();
});

test('a private relay address is accepted here', function () {
    // Deliberately not special-cased. A forwarding address is a real,
    // verified Apple address; it simply will not match a Unity member,
    // and refusing it here would move that refusal somewhere with less
    // context to explain it. The member gate is where it stops.
    $identity = appleProviderVerify(appleProviderToken(['email' => 'xyz@privaterelay.appleid.com']));

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe('xyz@privaterelay.appleid.com');
});

test('a token for another audience is refused', function () {
    // The provider passes the configured client id down as the
    // expected audience; this proves it passes the right one.
    expect(appleProviderVerify(appleProviderToken(['aud' => 'com.example.someone-else'])))->toBeNull();
});

test('a server side call is refused outright', function () {
    $provider = appleProvider();

    expect($provider->isServerSide())->toBeFalse();

    $provider->getAuthorizationUrl('state', 'nonce', 'https://example.org/callback');
})->throws(\LogicException::class);

test('handling a callback is refused outright', function () {
    // Apple has no browser leg. Reaching this would mean the registry
    // dispatched a client-side provider down the server-side path,
    // which is a wiring fault and should be loud.
    appleProvider()->handleCallback('code', 'nonce', 'https://example.org/callback');
})->throws(\LogicException::class);

function appleProvider(): AppleProvider
{
    return new AppleProvider(new Settings(), new JwtVerifier());
}

function appleProviderVerify(string $jwt): ?VerifiedIdentity
{
    FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [appleProviderJwk()]]));

    return appleProvider()->verifyIdToken($jwt, APPLE_PROVIDER_NONCE);
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function appleProviderToken(array $overrides = [], array $remove = []): string
{
    $claims = array_merge([
        'iss'            => APPLE_PROVIDER_ISSUER,
        'aud'            => APPLE_PROVIDER_AUDIENCE,
        'sub'            => '000123.abc.456',
        'email'          => 'member@example.org',
        'email_verified' => 'true',
        'nonce'          => APPLE_PROVIDER_NONCE,
        'iat'            => time(),
        'exp'            => time() + 600,
    ], $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    $header = appleProviderBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => APPLE_PROVIDER_KID, 'typ' => 'JWT']));
    $payload = appleProviderBase64Url((string) json_encode($claims));

    $signature = '';
    openssl_sign($header . '.' . $payload, $signature, test()->key, OPENSSL_ALGO_SHA256);

    return $header . '.' . $payload . '.' . appleProviderBase64Url($signature);
}

/**
 * @return array<string, string>
 */
function appleProviderJwk(): array
{
    $details = openssl_pkey_get_details(test()->key);
    expect($details)->toBeArray();

    return [
        'kty' => 'RSA',
        'kid' => APPLE_PROVIDER_KID,
        'use' => 'sig',
        'alg' => 'RS256',
        'n'   => appleProviderBase64Url($details['rsa']['n']),
        'e'   => appleProviderBase64Url($details['rsa']['e']),
    ];
}

function appleProviderBase64Url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
