<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * An enrolled Link handset.
 *
 * A device is the pairing of one installation of the Link app with one
 * Unity member. It is what a message is delivered *to*, and what a poll
 * or a send is authenticated *as*.
 *
 * The bearer token Link actually holds is never stored here — only its
 * HMAC (see {@see \Fellowship\Auth\DeviceTokenMinter}). A database dump
 * therefore yields no usable credentials, which matters because this
 * token is long-lived by design: a member should not be signed out of
 * their messages every twelve hours.
 *
 * `publicKey` is the half of the handset's own keypair it sent at
 * enrolment. The private half never leaves the device, so a message
 * sealed to this key can be opened by this handset and by nothing else —
 * this server included. That is the whole difference from Reach's
 * arrangement, where the server issues the key and keeps a copy.
 *
 * `memberEmail` is the identity the token was minted for. It is
 * re-resolved to a member and re-checked against {@see MemberGate} on
 * every authenticated request rather than trusted from this row, so
 * removing somebody from Unity stops their handset at the next call
 * without anyone remembering to revoke the device too.
 */
final class Device
{
    /** Platforms a device may report. Anything else is refused at enrolment. */
    public const PLATFORMS = ['android', 'ios'];

    /** Push transports. The empty string means "pull only" — see {@see wantsPush()}. */
    public const PUSH_NONE = '';
    public const PUSH_FCM = 'fcm';

    public function __construct(
        public readonly int $id,
        public readonly string $memberEmail,
        public readonly int $memberId,
        public readonly string $label,
        public readonly string $platform,
        public readonly string $publicKey,
        public readonly string $pushProvider,
        public readonly string $pushToken,
        public readonly int $createdAt,
        public readonly int $lastSeenAt = 0,
        public readonly ?int $revokedAt = null,
        /**
         * When this handset last reported it could not open a message, or
         * null if it never has.
         *
         * Reported by the handset rather than inferred: Fellowship can see
         * that a row has no public key, but not that a handset has lost
         * the private half — a keystore cleared by a factory reset, a
         * restored backup, a key invalidated when the screen lock changed.
         * From here such a handset looks healthy right up until a message
         * it cannot read, so it has to be able to say so.
         */
        public readonly ?int $keyFaultAt = null,
    ) {
    }

    /**
     * Whether this device has been revoked — by an admin from the Devices
     * page, or by the handset itself signing out.
     *
     * A revoked row is kept rather than deleted so the admin list can
     * still show that a handset was once enrolled and when it was cut off.
     * Nothing authenticates against it: the repository's lookup by token
     * hash refuses revoked rows outright, so a revoked token is
     * indistinguishable from an unknown one at every call site.
     */
    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /** Whether this handset has told us it cannot open its messages. */
    public function hasKeyFault(): bool
    {
        return $this->keyFaultAt !== null;
    }

    /**
     * Whether a message for this device should be pushed through FCM.
     *
     * All three are required. A device can claim the FCM transport but
     * have no token yet — the app enrols before Firebase hands one over —
     * and a device with no public key cannot be sent a sealed payload at
     * all. Either combination must fall back to the handset collecting its
     * own messages on the next poll rather than producing a push to
     * nowhere.
     */
    public function wantsPush(): bool
    {
        return $this->pushProvider === self::PUSH_FCM
            && $this->pushToken !== ''
            && $this->publicKey !== '';
    }

    /**
     * Normalise a claimed platform to one of {@see PLATFORMS}, or '' if it
     * is not one we recognise. Callers treat '' as a bad request — the
     * platform decides the delivery path, so guessing would mean silently
     * enrolling a handset that never receives anything.
     */
    public static function normalisePlatform(string $platform): string
    {
        $platform = strtolower(trim($platform));
        return in_array($platform, self::PLATFORMS, true) ? $platform : '';
    }
}
