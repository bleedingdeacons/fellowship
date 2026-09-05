<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Auth\Providers\OAuthProvider;
use Fellowship\Auth\VerifiedIdentity;

/**
 * A provider that verifies whatever it is given.
 *
 * The provider implementations have their own tests; what this controller
 * needs is something that answers a known identity so the tests are about
 * enrolment rather than about JWKS.
 */
final class StubProvider implements OAuthProvider
{
    public ?VerifiedIdentity $identity = null;

    public function __construct(
        private readonly string $name,
        private readonly bool $serverSide,
    ) {
        $this->identity = new VerifiedIdentity('member@example.org', $name, 'sub-1');
    }

    public function name(): string
    {
        return $this->name;
    }

    public function isServerSide(): bool
    {
        return $this->serverSide;
    }

    public function requiresPkce(): bool
    {
        return false;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        return 'https://accounts.example.org/authorize?state=' . $state;
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        return $this->identity;
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        return $this->identity;
    }
}
