<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Auth\BringsOwnClient;
use Fellowship\Auth\ProviderClient;
use Fellowship\Auth\SignInAudience;
use Fellowship\Auth\VerifiedIdentity;

/**
 * Another plugin's audience that signs its people in with its own client —
 * Freedom on behalf of Register, as Fellowship sees it.
 *
 * Admits the tablet address, sends codes only to its one redirect, and
 * records every provider and context it was asked for a client about, so
 * a test can see the start and the callback asked the same question.
 */
final class StubClientAudience implements SignInAudience, BringsOwnClient
{
    /** @var list<array{string, string}> */
    public array $clientRequests = [];

    public function __construct(
        public ?ProviderClient $client = null,
        private readonly string $name = 'freedom',
        private readonly string $redirect = 'org.example.app.freedom://auth',
    ) {
        $this->client ??= new ProviderClient('register-client.apps.googleusercontent.com', 'register-secret');
    }

    public function name(): string
    {
        return $this->name;
    }

    public function allowsRedirect(string $redirectUri, string $context): bool
    {
        return $redirectUri === $this->redirect;
    }

    public function refusalFor(VerifiedIdentity $identity, string $context): ?string
    {
        return $identity->email === 'tablet@example.org' ? null : 'not_authorised';
    }

    public function clientFor(string $provider, string $context): ?ProviderClient
    {
        $this->clientRequests[] = [$provider, $context];

        return $this->client;
    }
}
