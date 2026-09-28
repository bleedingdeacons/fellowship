<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;
use Fellowship\Logger\HasLogger;

/**
 * Link's own rules for the browser leg, exactly as they were before
 * audiences existed: the code goes only to `link://auth` or a developer's
 * loopback listener, and only to a Unity member.
 *
 * The member check still happens here, in the browser, as well as at
 * exchange — so somebody whose address is not a member's is told so where
 * they can read it, rather than by an opaque failure two steps later
 * inside the app.
 */
final class LinkAudience implements SignInAudience
{
    use HasLogger;

    public const NAME = 'link';

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly DeviceRedirectValidator $redirects,
        private readonly MemberGate $gate,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function allowsRedirect(string $redirectUri, string $context): bool
    {
        return $this->redirects->isAllowed($redirectUri);
    }

    public function refusalFor(VerifiedIdentity $identity, string $context): ?string
    {
        if ($this->gate->authorisedMember($identity->email) !== null) {
            return null;
        }

        self::logInfo('Sign-in refused: the verified address is not a member', [
            'provider' => $identity->provider,
        ]);

        return 'not_a_member';
    }
}
