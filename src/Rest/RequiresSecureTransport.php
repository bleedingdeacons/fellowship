<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use WP_Error;

/**
 * Refuses a request that did not arrive over TLS.
 *
 * Every Fellowship route carries either a credential or a member's
 * messages, so none of them has a plaintext form. The sealed payload
 * protects a message from Google; it does not protect a bearer token
 * from the coffee shop, and only HTTPS does that.
 *
 * `FELLOWSHIP_ALLOW_INSECURE_TRANSPORT` exists for local development
 * against a Local-by-Flywheel site with no certificate. It is a
 * wp-config.php constant rather than a setting on purpose: a checkbox in
 * the admin would eventually be ticked on a live site by somebody
 * debugging.
 */
trait RequiresSecureTransport
{
    private function insecureTransport(): ?WP_Error
    {
        if (is_ssl()) {
            return null;
        }

        if (defined('FELLOWSHIP_ALLOW_INSECURE_TRANSPORT') && FELLOWSHIP_ALLOW_INSECURE_TRANSPORT) {
            return null;
        }

        return new WP_Error(
            'fellowship_insecure_transport',
            'This endpoint requires HTTPS.',
            ['status' => 403],
        );
    }
}
