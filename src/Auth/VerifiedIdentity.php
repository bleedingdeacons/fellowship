<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * An email address a provider has told us, with a verified signature,
 * that this person controls.
 *
 * It is not yet an authorisation. {@see \Fellowship\Devices\MemberGate}
 * decides separately whether the address belongs to a Unity member; this
 * only says the person at the handset is who the address says.
 */
final class VerifiedIdentity
{
    public function __construct(
        public readonly string $email,
        public readonly string $provider,
        public readonly string $sub,
    ) {
    }
}
