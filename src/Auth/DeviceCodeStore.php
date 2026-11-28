<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The one-time code handed back to the app after a browser sign-in, and
 * exchanged by the app, through its own plugin, for its own credential.
 *
 * <b>Why there is a code at all.</b> The OAuth callback arrives in the
 * system browser, which cannot be trusted with a long-lived credential
 * and cannot hand one to the app without putting it in a URL — where it
 * lands in browser history, in any redirect logging in between, and in
 * the app's own launch intent. So the browser leg ends with a value that
 * is worthless two minutes later and worthless once used, and the app
 * spends it over TLS from its own process for the credential it keeps.
 *
 * Stored keyed by SHA-256 of the code, so the transient table holds no
 * usable code either.
 *
 * <b>A code is issued for one audience and spendable only there.</b>
 * Freedom's exchange redeems for `freedom`, and a code presented to the
 * wrong audience is spent and refused — spent first, so that
 * trying it at the wrong door cannot be followed by trying it at the
 * right one. See {@see SignInAudience}.
 */
final class DeviceCodeStore
{
    private const PREFIX = 'fellowship_device_code_';

    /** Long enough for a redirect back into the app, short enough to be worthless if captured. */
    private const TTL_SECONDS = 120;

    public function issue(
        VerifiedIdentity $identity,
        string $audience,
        string $context = '',
    ): string {
        $code = bin2hex(random_bytes(32));

        set_transient(
            self::PREFIX . $this->key($code),
            [
                'email'    => $identity->email,
                'provider' => $identity->provider,
                'sub'      => $identity->sub,
                'audience' => $audience,
                'context'  => $context,
            ],
            self::TTL_SECONDS,
        );

        return $code;
    }

    /**
     * Spend a code for the audience presenting it.
     *
     * The transient is deleted before the audience is compared, so a code
     * is single-use whoever presents it.
     */
    public function redeem(string $code, string $audience): ?BrokeredIdentity
    {
        if ($code === '') {
            return null;
        }

        $key = self::PREFIX . $this->key($code);
        $stored = get_transient($key);
        if (!is_array($stored)) {
            return null;
        }

        delete_transient($key);

        $email = (string) ($stored['email'] ?? '');
        if ($email === '') {
            return null;
        }

        // A code written before audiences existed was Link's, which nothing
        // redeems any more.
        $issuedFor = (string) ($stored['audience'] ?? '');
        if ($issuedFor === '' || $issuedFor === AudienceRegistry::RESERVED || !hash_equals($issuedFor, $audience)) {
            return null;
        }

        return new BrokeredIdentity(
            new VerifiedIdentity(
                email: $email,
                provider: (string) ($stored['provider'] ?? ''),
                sub: (string) ($stored['sub'] ?? ''),
            ),
            (string) ($stored['context'] ?? ''),
        );
    }

    private function key(string $code): string
    {
        return hash('sha256', $code);
    }
}
