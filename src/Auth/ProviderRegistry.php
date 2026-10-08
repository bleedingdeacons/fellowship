<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\ProviderRegistry as GuardianProviderRegistry;

/**
 * Fellowship's old name for Guardian's provider registry.
 *
 * The registry moved to the Guardian library with the providers. This empty
 * subclass exists only because Freedom's test harness builds an
 * IdentityBroker with `new Fellowship\Auth\ProviderRegistry()`, and
 * IdentityBroker now takes Guardian's — which this still is. Fellowship
 * itself uses Guardian's directly.
 *
 * @deprecated Use {@see GuardianProviderRegistry}. Removed once Freedom's
 *             tests have moved to it.
 */
final class ProviderRegistry extends GuardianProviderRegistry
{
}
