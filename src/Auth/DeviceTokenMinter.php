<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Mints the long-lived bearer token a handset authenticates with, and
 * turns one back into the value stored against its row.
 *
 * <b>HMAC, not a bare hash.</b> The stored value is keyed on the site's
 * auth salt, so an attacker holding a database dump cannot test candidate
 * tokens offline without also holding wp-config.php. A plain SHA-256
 * would let them, and 64 hex characters of entropy is only expensive to
 * brute force while the search space is the whole space.
 */
final class DeviceTokenMinter
{
    /** Distinguishes a Fellowship token at a glance in a log or a bug report. */
    public const TOKEN_PREFIX = 'fdt_';

    private const TOKEN_BYTES = 32;

    public function mint(): string
    {
        return self::TOKEN_PREFIX . bin2hex(random_bytes(self::TOKEN_BYTES));
    }

    public function hash(string $token): string
    {
        return hash_hmac('sha256', $token, $this->key());
    }

    /**
     * Whether a candidate has the shape of one of our tokens.
     *
     * Checked before the database lookup so a request carrying somebody
     * else's bearer token — a WordPress application password, a JWT from
     * another plugin — costs a regex rather than a query.
     */
    public function looksLikeToken(string $candidate): bool
    {
        return (bool) preg_match(
            '/^' . preg_quote(self::TOKEN_PREFIX, '/') . '[0-9a-f]{' . (self::TOKEN_BYTES * 2) . '}$/',
            $candidate,
        );
    }

    public function bearerFrom(string $authorizationHeader): string
    {
        if (!preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $authorizationHeader, $matches)) {
            return '';
        }

        return $matches[1];
    }

    private function key(): string
    {
        return hash('sha256', wp_salt('auth') . '|fellowship-device-token', true);
    }
}
