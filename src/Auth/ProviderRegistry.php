<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\Providers\OAuthProvider;

/**
 * The providers this site will accept a sign-in from.
 *
 * Registration is the permission model: a provider that is not in here
 * is not merely unconfigured, it is unreachable — the start route
 * answers 400 for a name it does not hold, and there is no second check
 * downstream. Adding Microsoft or Facebook later means registering them
 * in the service provider, and nothing else.
 */
final class ProviderRegistry
{
    /** @var array<string, OAuthProvider> */
    private array $providers = [];

    public function register(OAuthProvider $provider): void
    {
        $this->providers[strtolower($provider->name())] = $provider;
    }

    public function get(string $name): ?OAuthProvider
    {
        return $this->providers[strtolower($name)] ?? null;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->providers);
    }
}
