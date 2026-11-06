<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A device on Firebase that has presented a good token, and the member behind it.
 *
 * Its id is a string, so this isn't a {@see Device}, which is a row in WordPress.
 */
final class FirebaseDevice
{
    public function __construct(
        public readonly string $id,
        public readonly int $memberId,
        public readonly string $email,
        public readonly string $platform,
    ) {
    }
}
