<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Credentials\CredentialStore;
use LogicException;

/**
 * One audience's client, in the shape a Guardian provider reads credentials
 * from.
 *
 * Answers for the one provider it was made for and is empty for every
 * other, so a provider built around it can only ever use that client.
 * Read-only: a settings screen writes to the audience's own store, never
 * through here.
 */
final class FixedCredentials implements CredentialStore
{
    public function __construct(
        private readonly string $provider,
        private readonly ProviderClient $client,
    ) {
    }

    public function getClientId(string $provider): string
    {
        return $provider === $this->provider ? $this->client->clientId : '';
    }

    public function setClientId(string $provider, string $value): void
    {
        throw new LogicException('An audience\'s client is read-only here.');
    }

    public function getClientSecret(string $provider): string
    {
        return $provider === $this->provider ? $this->client->clientSecret : '';
    }

    public function setClientSecret(string $provider, string $value): void
    {
        throw new LogicException('An audience\'s client is read-only here.');
    }
}
