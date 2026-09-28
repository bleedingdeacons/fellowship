<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Whoever a browser sign-in is being done for.
 *
 * <b>Why this exists.</b> Fellowship's browser leg — Google's consent
 * screen, the callback, the one-time code — was written for Link, and
 * two of its rules were Link's rather than the flow's: the only redirect
 * it would hand a code to was `link://auth`, and the only people it
 * would hand one to were Unity members. Another plugin that wants a
 * Google-verified address (Freedom, for tablets signed in with a shared
 * account that is nobody's membership) needs the flow without those two
 * rules. So the rules moved here, and the flow asks whichever audience
 * started the sign-in.
 *
 * <b>The audience is fixed when the sign-in starts</b> and travels in
 * the state and then in the code, so a code issued for one audience is
 * refused by every other. See {@see DeviceCodeStore::redeem()}.
 *
 * `$context` is the audience's own opaque string — Freedom puts its
 * application and PKCE challenge in it. Fellowship stores it, carries it
 * and hands it back, and never reads it.
 */
interface SignInAudience
{
    /** Lower-case, `[a-z0-9_-]{1,32}`. Stored in the state and the code. */
    public function name(): string;

    /** Whether a code may be handed to this redirect target. */
    public function allowsRedirect(string $redirectUri, string $context): bool;

    /**
     * Null to admit this verified identity; otherwise the `error` value
     * the browser is sent back with, which the app shows its user.
     */
    public function refusalFor(VerifiedIdentity $identity, string $context): ?string;
}
