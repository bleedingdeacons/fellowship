<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

use WP_Role;

/**
 * Fellowship's own capabilities, granted to the administrator role.
 *
 * Separated from "can read personal data" (which Scrutiny owns) because
 * they answer different questions. A committee secretary may need to
 * send to their committee without being trusted to revoke somebody's
 * handset, and an intergroup officer reviewing the message log needs
 * neither.
 *
 * Granted on every load rather than only at activation: an update over
 * an active plugin never fires the activation hook, so a capability
 * introduced in a release would otherwise never reach an existing site
 * and the buttons it guards would go dead for everyone.
 */
final class Capabilities
{
    /** Compose and send a message to members or a committee. */
    public const SEND_MESSAGES = 'fellowship_send_messages';

    /** Revoke or remove an enrolled handset. */
    public const MANAGE_DEVICES = 'fellowship_manage_devices';

    public const ALL = [self::SEND_MESSAGES, self::MANAGE_DEVICES];

    public static function ensureAssigned(): void
    {
        $role = get_role('administrator');
        if (!$role instanceof WP_Role) {
            return;
        }

        foreach (self::ALL as $capability) {
            if (!$role->has_cap($capability)) {
                $role->add_cap($capability);
            }
        }
    }
}
