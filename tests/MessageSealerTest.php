<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Crypto\MessageSealer;

/**
 * The wire format, tested by actually opening the envelope.
 *
 * <b>This is the most load-bearing test in the plugin.</b> Everything
 * else can be checked by reading it; this cannot. The sealed payload is
 * produced here and opened by C# on a handset, and the two ends agree
 * only if a long list of details match — OAEP's hash, the nonce length,
 * the tag position, the gzip, the base64. A mismatch in any of them fails
 * on the phone, silently, as a message that arrives and will not open.
 *
 * So the test does the app's half in PHP: unwrap the content key with the
 * private half of a real keypair, split the envelope the way Link splits
 * it, decrypt, un-gzip, and compare. The other half of the contract is
 * `MessagePayloadCipherTests` in the Link solution, which builds an
 * envelope in C# the way this class builds one and opens it with the
 * shipping cipher. <b>Each side's test does the other side's job, so
 * drift on either turns the opposite one red.</b> If one changes, both
 * change.
 *
 * The keypair is generated per test rather than committed, so no private
 * key is ever in this repository.
 */

const MESSAGE_SEALER_IV_BYTES = 12;

const MESSAGE_SEALER_TAG_BYTES = 16;

test('a sealed payload can be opened with the private key', function () {
    [$publicKey, $privateKey] = messageSealerKeypair();

    $payload = [
        'id'      => 42,
        'subject' => 'Intergroup meeting moved',
        'body'    => 'September intergroup is now the 14th, same room.',
        'sender'  => 'Dave B',
    ];

    $sealed = (new MessageSealer())->seal($payload, $publicKey);

    expect($sealed)->toBeArray();
    expect($sealed)->toHaveKey('k');
    expect($sealed)->toHaveKey('p');

    expect(messageSealerOpen($sealed, $privateKey))->toBe($payload);
});

test('each seal uses a fresh content key', function () {
    // GCM fails catastrophically if a key and nonce are ever reused,
    // and the guarantee that they are not is "a new key every time".
    // Two seals of identical input must therefore share nothing.
    [$publicKey, $privateKey] = messageSealerKeypair();

    $sealer = new MessageSealer();
    $first  = $sealer->seal(['body' => 'same'], $publicKey);
    $second = $sealer->seal(['body' => 'same'], $publicKey);

    expect($first)->toBeArray();
    expect($second)->toBeArray();

    expect($second['k'])->not->toBe($first['k']);
    expect($second['p'])->not->toBe($first['p']);

    // Both still open to the same plaintext.
    expect(messageSealerOpen($second, $privateKey))->toBe(messageSealerOpen($first, $privateKey));
});

test('another handsets key does not open it', function () {
    // The whole point of the scheme: an envelope is readable by the
    // device it was sealed to and by nothing else — this server
    // included, since it never held the private half.
    [$publicKey] = messageSealerKeypair();
    [, $strangersPrivateKey] = messageSealerKeypair();

    $sealed = (new MessageSealer())->seal(['body' => 'private'], $publicKey);
    expect($sealed)->toBeArray();

    $contentKey = '';
    expect(openssl_private_decrypt(
        base64_decode($sealed['k'], true) ?: '',
        $contentKey,
        $strangersPrivateKey,
        OPENSSL_PKCS1_OAEP_PADDING,
    ))->toBeFalse();
});

test('an unusable key is refused rather than producing an empty payload', function (string $key) {
    // Null means "this handset cannot be sent to". An empty payload
    // would be read by the app as a message with no content, which is
    // the failure this return type exists to prevent.
    expect((new MessageSealer())->seal(['body' => 'hello'], $key))->toBeNull();
})->with([
    'empty'           => [''],
    'not a key'       => ['not-a-key'],
    'base64 of prose' => [base64_encode('hello there, I am not a key')],
]);

test('the worst case payload the API accepts fits inside an FCM data message', function () {
    // FCM caps a data message at 4096 bytes, and the wrapped key alone
    // is 344 base64 characters of it. The caps in MessageRequest are
    // what make this a known quantity; if either moves, this is the
    // test that says so.
    //
    // Built from random bytes rather than prose, because prose
    // compresses hard and would prove nothing about the ceiling.
    [$publicKey] = messageSealerKeypair();

    $sealed = (new MessageSealer())->seal([
        'id'         => 999999,
        'uuid'       => '123e4567-e89b-12d3-a456-426614174000',
        'subject'    => bin2hex(random_bytes(100)),   // 200 chars
        'body'       => bin2hex(random_bytes(1000)),  // 2000 chars
        'sender'     => str_repeat('x', 200),
        'sender_id'  => 999999,
        'created_at' => 1893456000,
        'reply_to'   => 999999,
        'read_at'    => 1893456000,
    ], $publicKey);

    expect($sealed)->toBeArray();

    // Both data keys travel too, and count against the same budget.
    $onTheWire = strlen('k') + strlen($sealed['k']) + strlen('p') + strlen($sealed['p']);

    expect($onTheWire)->toBeLessThan(4096, 'The largest message the API accepts must still fit in an FCM data message.');
});

/**
 * Do what the Link app does: unwrap, split, decrypt, inflate.
 *
 * @param array{k: string, p: string} $sealed
 * @return array<string, mixed>
 */
function messageSealerOpen(array $sealed, string $privateKeyPem): array
{
    $contentKey = '';
    expect(openssl_private_decrypt(
        base64_decode($sealed['k'], true) ?: '',
        $contentKey,
        $privateKeyPem,
        OPENSSL_PKCS1_OAEP_PADDING,
    ))->toBeTrue('The content key should unwrap with the private half of the keypair.');

    expect(strlen($contentKey))->toBe(32, 'The content key should be an AES-256 key.');

    $raw = base64_decode($sealed['p'], true);
    expect($raw)->toBeString();

    $compressed = openssl_decrypt(
        substr($raw, MESSAGE_SEALER_IV_BYTES + MESSAGE_SEALER_TAG_BYTES),
        'aes-256-gcm',
        $contentKey,
        OPENSSL_RAW_DATA,
        substr($raw, 0, MESSAGE_SEALER_IV_BYTES),
        substr($raw, MESSAGE_SEALER_IV_BYTES, MESSAGE_SEALER_TAG_BYTES),
    );

    expect($compressed)->toBeString('The payload should decrypt and authenticate.');

    $json = gzdecode($compressed);
    expect($json)->toBeString();

    $decoded = json_decode($json, true);
    expect($decoded)->toBeArray();

    return $decoded;
}

/**
 * A real RSA-2048 keypair, as base64 SPKI and PEM private key —
 * exactly the pair a handset generates and half-sends at enrolment.
 *
 * @return array{0: string, 1: string}
 */
function messageSealerKeypair(): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($resource === false) {
        // Without a usable openssl.cnf, key generation fails and every
        // assertion below would be about the environment rather than
        // the code. Say so plainly — this is the OPENSSL_CONF trap that
        // silently skips fifty RSA tests elsewhere in this suite.
        test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $privateKey = '';
    openssl_pkey_export($resource, $privateKey);

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    $base64Spki = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';

    return [$base64Spki, $privateKey];
}
