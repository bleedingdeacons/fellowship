<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A live Link enrolment, as another plugin is allowed to see it.
 *
 * What {@see IdentityBroker::sessionFor()} answers for a Firebase ID token.
 * Deliberately narrower than the device: another plugin has no business with
 * its push token or public key, and a narrower object is one that can change
 * underneath less.
 *
 * The device id is Firebase's (`d_…`). It stays typed int|string because
 * Freedom's tablets stored numeric ids from Fellowship's old table, and a
 * plugin compiled against either shape still loads.
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
