<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Auth\SignInAudience;
use Fellowship\Auth\VerifiedIdentity;

/**
 * Another plugin's audience, as the broker and the callback see it.
 *
 * Admits whoever is listed and sends codes only to its one redirect, and
 * records the context it was asked about, so a test can check that the
 * context travelled from start to callback untouched.
 */
final class StubAudience implements SignInAudience
{
    /** @var list<string> */
    public array $contextsSeen = [];

    /** @param list<string> $admits */
    public function __construct(
        private readonly string $name = 'freedom',
        private readonly string $redirect = 'org.example.app.freedom://auth',
        private readonly array $admits = ['tablet@example.org'],
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function allowsRedirect(string $redirectUri, string $context): bool
    {
        $this->contextsSeen[] = $context;

        return $redirectUri === $this->redirect;
    }

    public function refusalFor(VerifiedIdentity $identity, string $context): ?string
    {
        $this->contextsSeen[] = $context;

        return in_array($identity->email, $this->admits, true) ? null : 'not_authorised';
    }
}
