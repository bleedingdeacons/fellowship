<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A live Link enrolment, as another plugin is allowed to see it.
 *
 * What {@see IdentityBroker::sessionFor()} answers for a device token.
 * Deliberately not the {@see \Fellowship\Devices\Device} row: another
 * plugin has no business with the token hash, the push token or the
 * public key, and a narrower object is one that can change underneath
 * less.
 *
 * The device id is a string for a device on Firebase, and an int for one in
 * Fellowship's own table.
 */
final class LinkSession
{
    public function __construct(
        public readonly int|string $deviceId,
        public readonly string $email,
        public readonly int $memberId,
        public readonly string $platform,
    ) {
    }
}
