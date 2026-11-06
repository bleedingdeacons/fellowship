<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The outcome of checking a device's Firebase token.
 *
 * As {@see DeviceResolution}, with one more case: Firebase couldn't be asked. A
 * good token during a Google outage must not be told to sign in again.
 */
final class FirebaseDeviceResolution
{
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
        return new self(null, DeviceResolution::UNAUTHENTICATED);
    }

    public static function notAMember(): self
    {
        return new self(null, DeviceResolution::NOT_A_MEMBER);
    }

    public static function unavailable(): self
    {
        return new self(null, self::UNAVAILABLE);
    }
}
