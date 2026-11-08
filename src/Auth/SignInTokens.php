<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Guardian\Firebase\FirebaseIdTokenVerifier;
use Guardian\Jwt\JwtVerifier;

/**
 * Checks the Firebase sign-in a phone makes before it enrols, replaces a key or
 * takes over a device.
 *
 * The same rules the Functions applied when they asked this site:
 *
 * - <b>Google or Apple</b>, with a verified address; or
 * - <b>a Unity password</b>, as the custom token {@see FirebaseCustomTokenMinter}
 *   signed, carrying `identity: password` and the member id.
 *
 * Nothing else proves a person. Firebase also mints anonymous tokens and device
 * tokens, and both are refused.
 *
 * <b>Fresh, but not spent here.</b> A sign-in more than five minutes old is refused,
 * as the Functions refuse it. The Functions spend it, once, when it is used, so a
 * phone that asks here twice after a dropped answer isn't locked out.
 *
 * Not Guardian's {@see FirebaseIdTokenVerifier}: that spends the token, knows only
 * Google, and answers Google's subject, where the Functions need Firebase's uid.
 */
final class SignInTokens
{
    private const ISSUER_PREFIX = 'https://securetoken.google.com/';

    /** Matches MAX_AUTH_AGE_SECONDS in the Functions. */
    public const MAX_AUTH_AGE_SECONDS = 300;

    private const CLOCK_SKEW_SECONDS = 60;

    private const PROVIDERS_WITH_ADDRESS = ['google.com', 'apple.com'];

    /** @var Closure(): string */
    private readonly Closure $projectId;

    /**
     * @param callable(): string $projectId The Firebase project id, or '' when none
     *                                      is configured. Read per call.
     */
    public function __construct(
        private readonly JwtVerifier $verifier,
        callable $projectId,
    ) {
        $this->projectId = Closure::fromCallable($projectId);
    }

    public function verify(string $idToken): ?ProvenSignIn
    {
        $projectId = ($this->projectId)();
        if ($projectId === '' || substr_count($idToken, '.') !== 2) {
            return null;
        }

        $claims = $this->verifier->verify(
            $idToken,
            FirebaseIdTokenVerifier::JWKS_URL,
            self::ISSUER_PREFIX . $projectId,
            $projectId,
        );
        if ($claims === null) {
            return null;
        }

        // Firebase documents sub as the uid: non-empty, at most 128 chars.
        $uid = $claims['sub'] ?? null;
        if (!is_string($uid) || $uid === '' || strlen($uid) > 128) {
            return null;
        }

        $authTime = $claims['auth_time'] ?? null;
        if (!is_numeric($authTime)) {
            return null;
        }
        $age = time() - (int) $authTime;
        if ($age < -self::CLOCK_SKEW_SECONDS || $age > self::MAX_AUTH_AGE_SECONDS + self::CLOCK_SKEW_SECONDS) {
            return null;
        }

        $firebase = $claims['firebase'] ?? null;
        $provider = is_array($firebase) ? ($firebase['sign_in_provider'] ?? null) : null;

        if (in_array($provider, self::PROVIDERS_WITH_ADDRESS, true)) {
            $email = $claims['email'] ?? null;
            if (!is_string($email) || trim($email) === '' || ($claims['email_verified'] ?? null) !== true) {
                return null;
            }

            return ProvenSignIn::byEmail($uid, $email);
        }

        $memberId = $claims['memberId'] ?? null;
        if ($provider === 'custom' && ($claims['identity'] ?? null) === 'password' && is_int($memberId) && $memberId > 0) {
            return ProvenSignIn::byMemberId($uid, $memberId);
        }

        return null;
    }
}
