<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\VerifiedIdentity as ProviderIdentity;

/**
 * An email address a provider has told us, with a verified signature,
 * that this person controls.
 *
 * It is not yet an authorisation. {@see \Fellowship\Devices\MemberGate}
 * decides separately whether the address belongs to a Unity member; this
 * only says the person at the handset is who the address says.
 *
 * <b>Kept as Fellowship's own type although the providers now come from
 * Guardian.</b> It is part of the contract another plugin signs in through:
 * {@see SignInAudience::refusalFor()} and {@see BrokeredIdentity} carry it,
 * and Freedom implements and reads them. A provider's answer is converted
 * with {@see fromProvider()} at the two places one arrives — the browser
 * callback and the ID-token exchange — so that contract did not change when
 * the providers moved.
 */
final class VerifiedIdentity
{
    public function __construct(
        public readonly string $email,
        public readonly string $provider,
        public readonly string $sub,
    ) {
    }

    public static function fromProvider(ProviderIdentity $identity): self
    {
        return new self($identity->email, $identity->provider, $identity->sub);
    }
}
