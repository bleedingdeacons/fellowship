<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Symmetric encryption for data this site encrypts to itself and reads
 * back — settings secrets, and the stored copy of a message body.
 *
 * The key is derived from a WordPress salt, so a database dump alone
 * does not open it but this site always can. That is the right direction
 * for at-rest storage and exactly the wrong one for a push payload,
 * which has to be readable only by the handset it is addressed to — see
 * {@see \Fellowship\Crypto\MessageSealer}, which encrypts to a key the
 * server does not hold the other half of.
 *
 * Same construction as Reach's Cipher, deliberately: this is the shape
 * the suite already uses for at-rest secrets and there is no reason for
 * Fellowship to invent a second one.
 */
final class Cipher
{
    private const CIPHER = 'aes-256-gcm';
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    /**
     * $domain separates one use of this class from another, so a value
     * encrypted for settings cannot be decrypted as a message body even
     * though both derive from the same site salt.
     */
    public function __construct(private readonly string $domain)
    {
    }

    /** Returns '' when the cipher refuses; a caller must not store that as a value. */
    public function encrypt(string $plaintext): string
    {
        $iv = random_bytes(self::IV_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_BYTES,
        );

        if ($ciphertext === false) {
            return '';
        }

        return base64_encode($iv . $tag . $ciphertext);
    }

    /** Returns '' for anything that does not decrypt and authenticate. */
    public function decrypt(string $stored): string
    {
        $raw = base64_decode($stored, true);
        if ($raw === false || strlen($raw) < self::IV_BYTES + self::TAG_BYTES) {
            return '';
        }

        $iv         = substr($raw, 0, self::IV_BYTES);
        $tag        = substr($raw, self::IV_BYTES, self::TAG_BYTES);
        $ciphertext = substr($raw, self::IV_BYTES + self::TAG_BYTES);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        return $plaintext === false ? '' : $plaintext;
    }

    private function key(): string
    {
        return hash('sha256', wp_salt('auth') . '|' . $this->domain, true);
    }
}
