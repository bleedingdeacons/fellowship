<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Logger\HasLogger;
use Guardian\Credentials\CredentialStore;
use Guardian\ProviderRegistry;
use Guardian\Providers\OAuthProvider;

/**
 * The provider a browser sign-in uses: Fellowship's, unless its audience
 * brings a client of its own. See {@see BringsOwnClient}.
 *
 * <b>The registry stays the permission model.</b> A provider Fellowship
 * did not register is unreachable whatever an audience offers for it: the
 * registry is asked first, and only a provider it answers can be rebuilt
 * around another client.
 *
 * <b>Every doubt falls back to Fellowship's own client</b> — an audience
 * with nothing to offer, or a provider the factory cannot rebuild — which
 * is exactly how every sign-in behaved before audiences could bring one.
 */
final class AudienceProviders
{
    use HasLogger;

    /** @var Closure(string, CredentialStore): ?OAuthProvider */
    private readonly Closure $build;

    /**
     * @param callable(string, CredentialStore): ?OAuthProvider $build
     *        Builds the named provider around other credentials, or null
     *        for a provider it cannot.
     */
    public function __construct(
        private readonly ProviderRegistry $providers,
        callable $build,
    ) {
        $this->build = Closure::fromCallable($build);
    }

    /** Fellowship's own providers only: what a caller built before this existed gets. */
    public static function withoutOverrides(ProviderRegistry $providers): self
    {
        return new self($providers, static fn(string $name, CredentialStore $credentials): ?OAuthProvider => null);
    }

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function for(string $provider, SignInAudience $audience, string $context): ?OAuthProvider
    {
        $registered = $this->providers->get($provider);
        if ($registered === null || !$audience instanceof BringsOwnClient) {
            return $registered;
        }

        $client = $audience->clientFor($registered->name(), $context);
        if ($client === null) {
            return $registered;
        }

        $own = ($this->build)($registered->name(), new FixedCredentials($registered->name(), $client));
        if ($own === null || $own->name() !== $registered->name()) {
            self::logWarning('An audience brought its own client for a provider that cannot take one; using Fellowship\'s', [
                'audience' => $audience->name(),
                'provider' => $registered->name(),
            ]);

            return $registered;
        }

        // Which client, never its id or secret.
        self::logDebug('Sign-in uses the audience\'s own client', [
            'audience' => $audience->name(),
            'provider' => $registered->name(),
        ]);

        return $own;
    }
}
