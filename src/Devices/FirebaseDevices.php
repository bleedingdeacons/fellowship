<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Logger\HasLogger;
use Guardian\Firebase\FirebaseDeviceTokenVerifier;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Whether a device on Firebase may be believed right now.
 *
 * A signature isn't enough. An ID token lasts up to an hour and Firebase doesn't
 * check revocation inside it, so this makes the same three checks the Firestore
 * rules make, against the same document, and then re-runs the member gate:
 *
 * - it is a device's token, not a person's or anyone else's;
 * - the device is live, and the token isn't from before it was last cut off;
 * - the member is still admitted, which only WordPress can say.
 *
 * <b>A device's address isn't kept anywhere near it.</b> Firebase holds a member
 * id, and the email is read from Unity when needed.
 */
final class FirebaseDevices
{
    use HasLogger;

    /** @var Closure(): string */
    private readonly Closure $projectId;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * @param callable(): string $projectId The Firebase project id, or '' when none
     *                                      is configured. Read per call.
     */
    public function __construct(
        private readonly FirebaseDeviceTokenVerifier $verifier,
        callable $projectId,
        private readonly FirestoreClient $firestore,
        private readonly MemberRepository $members,
        private readonly MemberGate $gate,
    ) {
        $this->projectId = Closure::fromCallable($projectId);
    }

    /** Whether this could be a Firebase ID token, rather than Fellowship's own. */
    public static function looksLikeIdToken(string $token): bool
    {
        return substr_count($token, '.') === 2;
    }

    public function resolve(string $idToken): FirebaseDeviceResolution
    {
        $projectId = ($this->projectId)();
        if ($projectId === '' || !self::looksLikeIdToken($idToken)) {
            return FirebaseDeviceResolution::unauthenticated();
        }

        $token = $this->verifier->verify($idToken, $projectId);
        if ($token === null) {
            return FirebaseDeviceResolution::unauthenticated();
        }

        $memberId = $token->claims['memberId'] ?? null;
        if (($token->claims['kind'] ?? null) !== 'device' || !is_int($memberId) || $memberId <= 0) {
            return FirebaseDeviceResolution::unauthenticated();
        }

        try {
            $document = $this->firestore->get('devices/' . $token->uid);
        } catch (FirebaseUnavailable) {
            return FirebaseDeviceResolution::unavailable();
        }

        if ($document === null || ($document['status'] ?? null) !== 'live' || ($document['memberId'] ?? null) !== $memberId) {
            return FirebaseDeviceResolution::unauthenticated();
        }

        $validAfter = $document['tokensValidAfter'] ?? 0;
        if (!is_int($validAfter) || $token->authTime < $validAfter) {
            return FirebaseDeviceResolution::unauthenticated();
        }

        $member = $this->members->findById($memberId);
        if ($member === null || !$this->gate->isAuthorised($member)) {
            return FirebaseDeviceResolution::notAMember();
        }

        return FirebaseDeviceResolution::found(new FirebaseDevice(
            $token->uid,
            $memberId,
            strtolower(trim($member->getPersonalEmail())),
            is_string($document['platform'] ?? null) ? $document['platform'] : '',
        ));
    }

    /**
     * Whether this device is still one to accept a request from.
     *
     * <b>True when Firebase can't be asked.</b> A plugin calls this to stop trusting
     * a device whose enrolment has ended, not to admit one, and a Google outage
     * shouldn't cut off every tablet. The member gate needs no Firebase, so it is
     * still applied whenever the device's member is known.
     */
    public function isLive(string $deviceId): bool
    {
        if ($deviceId === '') {
            return false;
        }

        try {
            $document = $this->firestore->get('devices/' . $deviceId);
        } catch (FirebaseUnavailable) {
            self::logWarning('Could not check a Firebase device; treating it as live for now');

            return true;
        }

        if ($document === null || ($document['status'] ?? null) !== 'live') {
            return false;
        }

        $memberId = $document['memberId'] ?? null;
        if (!is_int($memberId)) {
            return false;
        }

        return $this->gate->isAuthorised($this->members->findById($memberId));
    }
}
