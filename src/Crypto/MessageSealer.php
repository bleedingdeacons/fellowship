<?php

declare(strict_types=1);

namespace Fellowship\Crypto;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Logger\HasLogger;

/**
 * Seals a message to one handset's own public key.
 *
 * <b>Hybrid, because RSA cannot carry a message.</b> An RSA-2048 key with
 * OAEP padding encrypts 214 bytes and no more — less than one paragraph.
 * So each message gets a fresh 32-byte content key, the body is sealed
 * under that with AES-256-GCM, and only the content key is encrypted to
 * the device. Two fields go on the wire: `k`, the wrapped content key,
 * and `p`, the sealed payload.
 *
 * A fresh key per message per device is not caution for its own sake: GCM
 * fails catastrophically if a key and nonce are ever reused, and the
 * surest way never to reuse one is never to keep one.
 *
 * <b>What this buys over the symmetric scheme Reach uses.</b> Reach
 * issues each handset a key and keeps a copy, so it can seal a payload
 * for a handset that enrolled months ago — and so can anyone holding both
 * its database and `wp-config.php`. Here the private half never leaves
 * the handset, so a payload this server sent yesterday is one it cannot
 * open today. The cost is that a lost key cannot be recovered, only
 * replaced: see {@see \Fellowship\Rest\DeviceAuthController::rotateKey()}.
 *
 * <b>OAEP with SHA-1, deliberately, and it is not a weakness.</b> PHP's
 * `openssl_public_encrypt()` with `OPENSSL_PKCS1_OAEP_PADDING` uses SHA-1
 * for the OAEP hash and MGF1, with no way to ask it for SHA-256 short of
 * the EVP API PHP does not expose. The app side matches it with
 * `RSAEncryptionPadding.OaepSHA1`. SHA-1's collision weakness is a
 * *signature* problem; OAEP relies on the hash's preimage resistance,
 * which is intact. Choosing SHA-256 here and discovering the mismatch on
 * the handset — where the failure is a message that arrives and decrypts
 * to nothing — is the more expensive mistake.
 *
 * <b>Everything is inside the envelope.</b> The sealed payload carries
 * the subject, the body, the sender and the message id together. Nothing
 * travels beside it in the clear for the handset to read first, because
 * it does not need anything first: it holds one key, it opens one blob,
 * and what is inside tells it what it has. What FCM and the notification
 * tray see is an opaque pair of fields.
 *
 * <b>Compressed before sealing, and that is load-bearing.</b> FCM caps a
 * data message at 4KB, and the wrapped key alone is 344 base64 characters
 * of it. A 2000-character body of incompressible text seals to roughly
 * 2.8KB, which fits; the same body as ordinary prose comes to a few
 * hundred bytes. The margin is comfortable rather than generous, so a
 * field added to the payload later should be measured against a worst
 * case rather than assumed to fit — see
 * {@see \Fellowship\Messaging\MessageRequest} for the caps that make the
 * worst case a known quantity.
 */
final class MessageSealer
{
    use HasLogger;

    private const CIPHER = 'aes-256-gcm';
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;
    private const CONTENT_KEY_BYTES = 32;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * Seal one map to a device public key.
     *
     * Returns `['k' => ..., 'p' => ...]`, or null when the key is unusable
     * or the cipher refuses. A caller must read null as "this handset
     * cannot be sent to" — never as an empty payload, which the app would
     * take for a message with no content.
     *
     * @param array<string, string|int> $data
     * @return array{k: string, p: string}|null
     */
    public function seal(array $data, string $base64PublicKey): ?array
    {
        $key = DevicePublicKey::load($base64PublicKey);
        if ($key === null) {
            self::logWarning('Message not sealed: the stored device public key could not be loaded');
            return null;
        }

        $json = wp_json_encode($data);
        if (!is_string($json)) {
            return null;
        }

        $compressed = gzencode($json);
        if (!is_string($compressed)) {
            return null;
        }

        $contentKey = random_bytes(self::CONTENT_KEY_BYTES);
        $iv = random_bytes(self::IV_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $compressed,
            self::CIPHER,
            $contentKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_BYTES,
        );

        if ($ciphertext === false) {
            return null;
        }

        $wrapped = '';
        if (!openssl_public_encrypt($contentKey, $wrapped, $key, OPENSSL_PKCS1_OAEP_PADDING)) {
            self::logWarning('Message not sealed: the content key could not be wrapped to the device key');
            return null;
        }

        return [
            'k' => base64_encode($wrapped),
            // The same envelope Reach packs — 12-byte nonce, 16-byte tag,
            // ciphertext, base64 — so the framing an app developer has to
            // implement is the one already written for Hand. Only what
            // carries the key differs.
            'p' => base64_encode($iv . $tag . $ciphertext),
        ];
    }
}
