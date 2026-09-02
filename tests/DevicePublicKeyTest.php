<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Crypto\DevicePublicKey;
use PHPUnit\Framework\TestCase;

/**
 * What a handset may offer as its public key, and what it may not.
 *
 * Each refusal here is a device that would otherwise enrol successfully
 * and then never receive a message — which is the failure mode the whole
 * validate-at-enrolment rule exists to prevent.
 */
final class DevicePublicKeyTest extends TestCase
{
    public function testABase64SpkiIsAccepted(): void
    {
        $key = $this->publicKey(2048);

        self::assertNotSame('', DevicePublicKey::normalise($key));
        self::assertNotNull(DevicePublicKey::load($key));
    }

    public function testArmouredPemIsAcceptedToo(): void
    {
        // A handset sending PEM has not done anything wrong, it has just
        // done the step this class was about to do. Refusing it would be
        // pedantry that costs a support conversation.
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split($this->publicKey(2048), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        self::assertNotSame('', DevicePublicKey::normalise($pem));
    }

    public function testTheStoredFormIsCanonicalRatherThanWhateverWasSent(): void
    {
        // Re-encoded from the parsed key, so what is stored is what OpenSSL
        // actually read — not whatever line wrapping the handset used.
        $key = $this->publicKey(2048);

        self::assertSame(
            DevicePublicKey::normalise($key),
            DevicePublicKey::normalise(chunk_split($key, 40, "\n")),
        );
    }

    public function testAKeyShorterThanTheFloorIsRefused(): void
    {
        self::assertSame('', DevicePublicKey::normalise($this->publicKey(1024)));
    }

    /**
     * @dataProvider rubbish
     */
    public function testRubbishIsRefused(string $submitted): void
    {
        self::assertSame('', DevicePublicKey::normalise($submitted));
        self::assertNull(DevicePublicKey::load($submitted));
    }

    /** @return array<string, array{0: string}> */
    public static function rubbish(): array
    {
        return [
            'empty'             => [''],
            'whitespace'        => ["   \n  "],
            'not base64'        => ['this is not a key at all!!'],
            'base64 of prose'   => [base64_encode('hello there, I am not a key')],
            'over the size cap' => [str_repeat('A', 5000)],
        ];
    }

    public function testAnEcKeyIsRefusedBecauseThisServerCannotEncryptToOne(): void
    {
        // Not a judgement on EC. PHP's openssl_public_encrypt() does RSA
        // and nothing else, so accepting one here would store a key that
        // MessageSealer can never use.
        $resource = openssl_pkey_new([
            'curve_name'       => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        if ($resource === false) {
            self::markTestSkipped('OpenSSL could not generate an EC keypair. Set OPENSSL_CONF.');
        }

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $spki = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';

        self::assertSame('', DevicePublicKey::normalise($spki));
    }

    /** Base64 SPKI for a fresh RSA key of the given size. */
    private function publicKey(int $bits): string
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }
}
