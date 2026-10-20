<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Guardian\Firebase\FirebaseIdTokenVerifier;

/**
 * Native Google sign-in, as Link does it on Android and iOS.
 *
 * The handset shows the platform's own account picker, hands the Google
 * credential to Firebase Auth, and sends the Firebase ID token as
 * `firebase_token` — to `/auth/device/exchange` to enrol, or to
 * `/auth/device/key` to prove itself before replacing a key. Guardian does
 * the verifying; what this adds is which Firebase project counts as ours.
 *
 * <b>The project comes from the FCM service account.</b> Fellowship
 * already holds one to push messages, and it names the project Link's
 * `google-services.json` and `GoogleService-Info.plist` belong to — which
 * is exactly the project a genuine Link's Firebase tokens are minted for.
 * A second setting would be a second place to get it wrong. Native
 * sign-in is therefore off until push is configured, and Link falls back
 * to the browser until it is.
 */
final class FirebaseSignIn
{
    /** @var Closure(): string */
    private readonly Closure $projectId;

    /**
     * @param callable(): string $projectId The Firebase project id, or '' when
     *                                      none is configured. Read per call,
     *                                      so a replaced service account takes
     *                                      effect without a restart.
     */
    public function __construct(
        private readonly FirebaseIdTokenVerifier $verifier,
        callable $projectId,
    ) {
        $this->projectId = Closure::fromCallable($projectId);
    }

    public function isConfigured(): bool
    {
        return ($this->projectId)() !== '';
    }

    public function verify(string $idToken): ?VerifiedIdentity
    {
        $projectId = ($this->projectId)();
        if ($projectId === '' || $idToken === '') {
            return null;
        }

        $proven = $this->verifier->verify($idToken, $projectId, FirebaseIdTokenVerifier::GOOGLE);

        return $proven !== null ? VerifiedIdentity::fromProvider($proven) : null;
    }
}
