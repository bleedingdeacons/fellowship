<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Logger\HasLogger;
use Fellowship\Push\ServiceAccount;

/**
 * Signs Firebase custom tokens with the service account Fellowship holds.
 *
 * <b>This is how a Unity password reaches Firebase.</b> A member has one
 * password, kept by Unity and shared with Reach, Sentinel and Amber, so
 * Firebase never sees it. Fellowship checks it and answers with one of these,
 * which the handset exchanges for a Firebase sign-in that proves who it is at
 * enrolment.
 *
 * <b>Five minutes, not the hour Firebase allows.</b> The token is exchanged
 * seconds after it is issued, and nothing is gained by leaving it useful for
 * longer than that takes.
 *
 * The token carries only an opaque id and the claims it is given. It is signed
 * here, and Firebase checks the signature when the handset presents it.
 */
final class FirebaseCustomTokenMinter
{
    use Base64Url;
    use HasLogger;

    /** Firebase's required audience for every custom token. */
    public const AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';

    private const TTL_SECONDS = 300;

    /** Firebase documents a uid as at most 128 characters. */
    private const UID_MAX_LENGTH = 128;

    /** @var Closure(): ?ServiceAccount */
    private readonly Closure $account;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * @param callable(): ?ServiceAccount $account Read per call, so a replaced
     *                                             service account takes effect
     *                                             without a restart.
     */
    public function __construct(callable $account)
    {
        $this->account = Closure::fromCallable($account);
    }

    public function isConfigured(): bool
    {
        return ($this->account)() !== null;
    }

    /**
     * @param array<string, scalar> $claims Copied onto the Firebase ID token.
     *
     * @return string|null The signed token, or null when it cannot be made.
     */
    public function mint(string $uid, array $claims = []): ?string
    {
        if ($uid === '' || strlen($uid) > self::UID_MAX_LENGTH) {
            return null;
        }

        $account = ($this->account)();
        if ($account === null) {
            return null;
        }

        $now = time();

        $payload = [
            'iss' => $account->clientEmail,
            'sub' => $account->clientEmail,
            'aud' => self::AUDIENCE,
            'iat' => $now,
            'exp' => $now + self::TTL_SECONDS,
            'uid' => $uid,
        ];
        if ($claims !== []) {
            $payload['claims'] = $claims;
        }

        $signingInput = $this->base64UrlEncode((string) wp_json_encode(['alg' => 'RS256', 'typ' => 'JWT']))
            . '.'
            . $this->base64UrlEncode((string) wp_json_encode($payload));

        $key = openssl_pkey_get_private($account->privateKey);
        if ($key === false) {
            self::logWarning('Service-account private key could not be read for a custom token');
            return null;
        }

        $signature = '';
        if (openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256) === false) {
            self::logWarning('Custom token could not be signed');
            return null;
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }
}
