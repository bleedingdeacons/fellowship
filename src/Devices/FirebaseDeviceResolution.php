<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The outcome of checking a device's Firebase token.
 *
 * <b>A member is told one thing; everyone else nothing.</b> A malformed token,
 * an unknown one and a revoked one are all `unauthenticated`, so the answer
 * says nothing about which. `not_a_member` is the one refusal a member can act
 * on: the token was good and the person behind it no longer is. And Firebase
 * couldn't be asked: a good token during a Google outage must not be told to
 * sign in again.
 */
final class FirebaseDeviceResolution
{
    /** No device to be found, and deliberately no reason given. */
    public const UNAUTHENTICATED = 'unauthenticated';

    /** The token was good and the person behind it is not, or no longer is, a member. */
    public const NOT_A_MEMBER = 'not_a_member';

    /** The token couldn't be checked because Firebase couldn't be reached. */
    public const UNAVAILABLE = 'unavailable';

    private function __construct(
        public readonly ?FirebaseDevice $device,
        public readonly string $refusal,
    ) {
    }

    public static function found(FirebaseDevice $device): self
    {
        return new self($device, '');
    }

    public static function unauthenticated(): self
    {
        return new self(null, self::UNAUTHENTICATED);
    }

    public static function notAMember(): self
    {
        return new self(null, self::NOT_A_MEMBER);
    }

    public static function unavailable(): self
    {
        return new self(null, self::UNAVAILABLE);
    }
}
