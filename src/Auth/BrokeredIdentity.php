<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A verified identity handed to another plugin, with the context that
 * plugin gave when it started the sign-in.
 *
 * The context comes back so the plugin can check it against what the app
 * is now claiming — Freedom compares the application and verifies the
 * PKCE challenge against it — rather than trusting the app to repeat it.
 */
final class BrokeredIdentity
{
    public function __construct(
        public readonly VerifiedIdentity $identity,
        public readonly string $context,
    ) {
    }
}
