<?php

declare(strict_types=1);

namespace Fellowship\Crypto;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The public half of the keypair a handset generates on first attach.
 *
 * <b>The wire format is base64 of a DER SubjectPublicKeyInfo</b> — the
 * bytes between the PEM armour, with no headers and no newlines. That is
 * what .NET's `RSA.ExportSubjectPublicKeyInfo()` hands back, so the app
 * sends what its platform already produces rather than assembling PEM by
 * hand. This class puts the armour back on before handing it to OpenSSL,
 * which is the only party that wants it.
 *
 * <b>Why the key is checked at enrolment rather than at first send.</b> A
 * key that will not load is a handset that can never be messaged, and the
 * only moment anybody is watching is enrolment. Deferred, the failure
 * surfaces as messages that silently never arrive, on a device whose
 * admin row looks perfectly healthy — which is the shape of bug this
 * whole layer is arranged to avoid.
 */
final class DevicePublicKey
{
    /**
     * Smallest RSA modulus accepted.
     *
     * 2048 rather than 3072 because the floor has to be one every
     * platform's hardware-backed keystore will actually generate:
     * RSA-2048 is universally available in Android's StrongBox and the
     * Apple Secure Enclave's software fallback, and a larger floor would
     * push key generation off the security chip on the handsets that most
     * need it there. Nothing stops a handset offering more, and one that
     * does is accepted as-is.
     */
    public const MIN_BITS = 2048;

    /**
     * Cap on the submitted string, before decoding.
     *
     * An RSA-4096 SPKI is about 736 bytes of base64; 4096 leaves room for
     * a larger key without letting an unauthenticated enrolment request
     * hand OpenSSL something enormous to parse.
     */
    private const MAX_ENCODED_BYTES = 4096;

    /**
     * Normalise a submitted public key, or return '' if it is not one we
     * can encrypt to.
     *
     * The returned string is the canonical base64 DER to store against
     * the device: re-encoded from the parsed key rather than echoed back,
     * so what is stored is what OpenSSL actually read and not whatever
     * whitespace or line wrapping the handset happened to send.
     */
    public static function normalise(string $submitted): string
    {
        $key = self::load($submitted);
        if ($key === null) {
            return '';
        }

        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['key']) || !is_string($details['key'])) {
            return '';
        }

        return self::stripArmour($details['key']);
    }

    /**
     * Load a submitted key as an OpenSSL public key, or null when it is
     * unusable — malformed, the wrong algorithm, or too short.
     */
    public static function load(string $submitted): ?\OpenSSLAsymmetricKey
    {
        $submitted = trim($submitted);
        if ($submitted === '' || strlen($submitted) > self::MAX_ENCODED_BYTES) {
            return null;
        }

        // Accept PEM as well as raw base64. A handset sending armoured PEM
        // has not done anything wrong, it has just done the step this
        // class was about to do; refusing it would be pedantry that costs
        // a support conversation.
        $der = str_contains($submitted, '-----BEGIN')
            ? self::stripArmour($submitted)
            : $submitted;

        // Strict base64: a key with stray characters in it is not a key we
        // should be guessing about.
        $raw = base64_decode(preg_replace('/\s+/', '', $der) ?? '', true);
        if (!is_string($raw) || $raw === '') {
            return null;
        }

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($raw), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            return null;
        }

        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            return null;
        }

        // RSA only, and only because that is what both ends can agree on
        // today: PHP's openssl_public_encrypt() does RSA and nothing else,
        // so an EC key here would need a hand-rolled ECDH and a KDF on
        // both sides. If that changes, this is the one place that has to
        // learn a second algorithm.
        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            return null;
        }

        if ((int) ($details['bits'] ?? 0) < self::MIN_BITS) {
            return null;
        }

        return $key;
    }

    /** The PEM body, with the BEGIN/END lines and all whitespace removed. */
    private static function stripArmour(string $pem): string
    {
        $body = preg_replace('/-----(BEGIN|END)[^-]*-----/', '', $pem) ?? '';
        return preg_replace('/\s+/', '', $body) ?? '';
    }
}
