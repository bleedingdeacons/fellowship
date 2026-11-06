<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\FirebaseCustomTokenMinter;
use Fellowship\Push\ServiceAccount;

/**
 * The custom tokens a Unity password becomes.
 *
 * Firebase rejects a custom token whose shape is wrong, and only at the moment
 * a member is signing in, so the shape is pinned here against Firebase's
 * documented claims, with a real key and a real signature check.
 */

covers(FirebaseCustomTokenMinter::class);

const CUSTOM_TOKEN_ACCOUNT = 'firebase-adminsdk@fellowship-510917.iam.gserviceaccount.com';

beforeEach(function () {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $pem = '';
    openssl_pkey_export($key, $pem);

    $this->publicKey = (string) openssl_pkey_get_details($key)['key'];
    $this->account = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => 'fellowship-510917',
        'client_email' => CUSTOM_TOKEN_ACCOUNT,
        'private_key'  => $pem,
    ]));
});

test('a token carries what Firebase requires', function () {
    $before = time();

    $claims = customTokenClaims(customTokenMinter()->mint('pw_7'));

    expect($claims['iss'])->toBe(CUSTOM_TOKEN_ACCOUNT);
    expect($claims['sub'])->toBe(CUSTOM_TOKEN_ACCOUNT);
    expect($claims['aud'])->toBe(FirebaseCustomTokenMinter::AUDIENCE);
    expect($claims['uid'])->toBe('pw_7');
    expect($claims['iat'])->toBeGreaterThanOrEqual($before);
});

test('a token is signed by the service account', function () {
    [$head, $body, $signature] = explode('.', (string) customTokenMinter()->mint('pw_7'));

    $verified = openssl_verify(
        $head . '.' . $body,
        customTokenDecode($signature),
        $this->publicKey,
        OPENSSL_ALGO_SHA256,
    );

    expect($verified)->toBe(1);
    expect(json_decode(customTokenDecode($head), true)['alg'])->toBe('RS256');
});

test('a token lasts five minutes, not the hour Firebase allows', function () {
    $claims = customTokenClaims(customTokenMinter()->mint('pw_7'));

    expect($claims['exp'] - $claims['iat'])->toBe(300);
});

test('claims are carried, and left out when there are none', function () {
    $with = customTokenClaims(customTokenMinter()->mint('pw_7', ['memberId' => 7, 'identity' => 'password']));
    $without = customTokenClaims(customTokenMinter()->mint('pw_7'));

    expect($with['claims'])->toBe(['memberId' => 7, 'identity' => 'password']);
    expect($without)->not->toHaveKey('claims');
});

test('a token never carries the private key or an address', function () {
    $token = (string) customTokenMinter()->mint('pw_7', ['memberId' => 7]);

    expect($token)->not->toContain('PRIVATE');
    expect(customTokenDecode(explode('.', $token)[1]))->not->toContain('member@example.org');
});

test('a uid Firebase would refuse is not signed', function (string $uid) {
    expect(customTokenMinter()->mint($uid))->toBeNull();
})->with([
    'empty'    => [''],
    'too long' => [str_repeat('a', 129)],
]);

test('no service account means no token', function () {
    $minter = new FirebaseCustomTokenMinter(static fn(): ?ServiceAccount => null);

    expect($minter->isConfigured())->toBeFalse();
    expect($minter->mint('pw_7'))->toBeNull();
});

test('a key that will not load means no token', function () {
    $broken = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => 'fellowship-510917',
        'client_email' => CUSTOM_TOKEN_ACCOUNT,
        'private_key'  => 'not a key',
    ]));

    $minter = new FirebaseCustomTokenMinter(static fn(): ?ServiceAccount => $broken);

    expect($minter->isConfigured())->toBeTrue();
    expect($minter->mint('pw_7'))->toBeNull();
});

function customTokenMinter(): FirebaseCustomTokenMinter
{
    $account = test()->account;

    return new FirebaseCustomTokenMinter(static fn(): ?ServiceAccount => $account);
}

/**
 * @return array<string, mixed>
 */
function customTokenClaims(?string $token): array
{
    expect($token)->not->toBeNull();

    return (array) json_decode(customTokenDecode(explode('.', (string) $token)[1]), true);
}

function customTokenDecode(string $part): string
{
    return (string) base64_decode(strtr($part, '-_', '+/'), true);
}
