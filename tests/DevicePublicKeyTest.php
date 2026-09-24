<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Crypto\DevicePublicKey;

/**
 * What a handset may offer as its public key, and what it may not.
 *
 * Each refusal here is a device that would otherwise enrol successfully
 * and then never receive a message — which is the failure mode the whole
 * validate-at-enrolment rule exists to prevent.
 */

test('a base64 SPKI is accepted', function () {
    $key = devicePublicKeyPublicKey(2048);

    expect(DevicePublicKey::normalise($key))->not->toBe('');
    expect(DevicePublicKey::load($key))->not->toBeNull();
});

test('armoured PEM is accepted too', function () {
    // A handset sending PEM has not done anything wrong, it has just
    // done the step this class was about to do. Refusing it would be
    // pedantry that costs a support conversation.
    $pem = "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(devicePublicKeyPublicKey(2048), 64, "\n")
        . "-----END PUBLIC KEY-----\n";

    expect(DevicePublicKey::normalise($pem))->not->toBe('');
});

test('the stored form is canonical rather than whatever was sent', function () {
    // Re-encoded from the parsed key, so what is stored is what OpenSSL
    // actually read — not whatever line wrapping the handset used.
    $key = devicePublicKeyPublicKey(2048);

    expect(DevicePublicKey::normalise(chunk_split($key, 40, "\n")))->toBe(DevicePublicKey::normalise($key));
});

test('a key shorter than the floor is refused', function () {
    expect(DevicePublicKey::normalise(devicePublicKeyPublicKey(1024)))->toBe('');
});

test('rubbish is refused', function (string $submitted) {
    expect(DevicePublicKey::normalise($submitted))->toBe('');
    expect(DevicePublicKey::load($submitted))->toBeNull();
})->with([
    'empty'             => [''],
    'whitespace'        => ["   \n  "],
    'not base64'        => ['this is not a key at all!!'],
    'base64 of prose'   => [base64_encode('hello there, I am not a key')],
    'over the size cap' => [str_repeat('A', 5000)],
]);

test('an EC key is refused because this server cannot encrypt to one', function () {
    // Not a judgement on EC. PHP's openssl_public_encrypt() does RSA
    // and nothing else, so accepting one here would store a key that
    // MessageSealer can never use.
    $resource = openssl_pkey_new([
        'curve_name'       => 'prime256v1',
        'private_key_type' => OPENSSL_KEYTYPE_EC,
    ]);

    if ($resource === false) {
        $this->markTestSkipped('OpenSSL could not generate an EC keypair. Set OPENSSL_CONF.');
    }

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    $spki = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';

    expect(DevicePublicKey::normalise($spki))->toBe('');
});

/** Base64 SPKI for a fresh RSA key of the given size. */
function devicePublicKeyPublicKey(int $bits): string
{
    $resource = openssl_pkey_new([
        'private_key_bits' => $bits,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($resource === false) {
        test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
}
