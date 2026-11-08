<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Auth\Base64Url;
use Fellowship\Logger\HasLogger;
use Fellowship\Push\ServiceAccount;

/**
 * Signs what Fellowship has decided, for a phone to hand to the Functions.
 *
 * <b>Why the phone carries it.</b> The Functions used to ask this site who was a
 * member and who a message reached. SiteGround challenges calls from Google Cloud's
 * shared addresses, so those questions failed whenever Google picked a flagged one.
 * Now the phone, which reaches the site, asks here instead, and passes the signed
 * answer on. The Functions check Google's copy of this key and call nobody.
 *
 * <b>The same trust, the other way round.</b> The service account signs these, and
 * the Functions run as it. Only this site and Google hold its key.
 *
 * <b>Five minutes.</b> A phone uses one within seconds. Each names the sign-in or
 * device it was issued to, so it is no use to anybody else.
 */
final class AttestationSigner
{
    use Base64Url;
    use HasLogger;

    public const KIND_MEMBER = 'member';
    public const KIND_AUDIENCE = 'audience';

    public const TTL_SECONDS = 300;

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

    /** Who the Functions expect a statement for. The project, so no other can use one. */
    public static function audience(string $projectId): string
    {
        return 'fellowship-functions:' . $projectId;
    }

    /** A key id is needed too: it is how the Functions find the public key. */
    public function isConfigured(): bool
    {
        $account = ($this->account)();

        return $account !== null && $account->privateKeyId !== '';
    }

    /**
     * @param array<string, mixed> $claims What was decided, beside the standard claims.
     *
     * @return string|null The signed statement, or null when it can't be made.
     */
    public function sign(string $kind, string $subject, array $claims): ?string
    {
        $account = ($this->account)();
        if ($account === null || $account->privateKeyId === '' || $subject === '') {
            return null;
        }

        $now = time();

        $payload = [
            'iss'  => $account->clientEmail,
            'aud'  => self::audience($account->projectId),
            'sub'  => $subject,
            'iat'  => $now,
            'exp'  => $now + self::TTL_SECONDS,
            'kind' => $kind,
        ] + $claims;

        $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $account->privateKeyId];

        $signingInput = $this->base64UrlEncode((string) wp_json_encode($header))
            . '.'
            . $this->base64UrlEncode((string) wp_json_encode($payload));

        $key = openssl_pkey_get_private($account->privateKey);
        if ($key === false) {
            self::logWarning('Service-account private key could not be read for an attestation');
            return null;
        }

        $signature = '';
        if (openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256) === false) {
            self::logWarning('An attestation could not be signed');
            return null;
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }
}
