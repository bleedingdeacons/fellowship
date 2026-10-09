<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * An audience that signs its people in with an OAuth client of its own.
 *
 * <b>Why this exists.</b> Fellowship has one Google client, and every
 * browser sign-in used it — Link's, and Freedom's on behalf of Register.
 * So a tablet signing in to Register was shown Link's consent screen and
 * counted against Link's Google Cloud project. An audience that implements
 * this can name its own client for a sign-in instead; Fellowship then
 * uses it for that sign-in's authorization URL, its code exchange and its
 * ID-token audience check, and nothing else changes.
 *
 * <b>Optional, and separate from {@see SignInAudience}</b>, so an audience
 * written before it existed keeps compiling and keeps Fellowship's client.
 *
 * Each such client must register Fellowship's own callback,
 * `fellowship/v1/auth/callback`, as an authorized redirect URI: the
 * browser leg still returns there whoever's client started it.
 */
interface BringsOwnClient
{
    /**
     * This sign-in's own client for `$provider` (a provider's lower-case
     * name), or null to use Fellowship's.
     *
     * Asked when the sign-in starts and again at the callback, with the
     * same context both times, so it must give the same answer for both.
     */
    public function clientFor(string $provider, string $context): ?ProviderClient;
}
