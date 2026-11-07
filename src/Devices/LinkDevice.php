<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * One enrolled handset, as the Devices screen shows it.
 *
 * What the screen needs and nothing it could misuse: whether there is a push token
 * rather than the token, and no key at all.
 */
final class LinkDevice
{
    public function __construct(
        public readonly string $id,
        public readonly int $memberId,
        public readonly string $platform,
        public readonly string $label,
        public readonly bool $hasPushToken,
        public readonly bool $keyFault,
        public readonly bool $revoked,
        public readonly int $createdAt = 0,
        public readonly int $lastSeenAt = 0,
        public readonly int $revokedAt = 0,
    ) {
    }
}
