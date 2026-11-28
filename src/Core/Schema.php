<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Logger\HasLogger;
use wpdb;

/**
 * Fellowship's schema version, and the one-off upgrades an update runs.
 *
 * <b>Fellowship creates no tables any more.</b> Link's devices and messages
 * live in Firestore, and password credentials are Unity's. What stays is the
 * version check: it is the one hook an existing site runs on update, so it is
 * where a clean-up has to live.
 *
 * <b>Why this is not just the activation hook.</b> That works exactly
 * once — the first time a site activates the plugin — and then quietly
 * stops being true. A site that *updates* Fellowship never runs
 * `register_activation_hook`: WordPress fires it on activation, and an
 * update over the top of an active plugin is not an activation. Neither
 * is a `GitHub Plugin URI` auto-update, which is how these sites take
 * new versions.
 *
 * Reach learned this the ugly way — enrolment appeared to succeed and
 * returned a device token, because `$wpdb->insert()` reports a missing
 * table by returning false rather than raising, and nothing checked. The
 * handset then 401'd on its very next request with nothing anywhere
 * saying why. Fellowship starts with the fix rather than the bug: keep a
 * schema version in an option, compare it on load, and run dbDelta when
 * it has moved. dbDelta is idempotent and diffs against the live schema,
 * so running it again costs one query when nothing has changed.
 *
 * <b>Bump {@see VERSION} whenever a table is added or a column
 * changes.</b> Nothing detects that for you; an unbumped version means
 * the change reaches new installs and silently skips every existing one.
 */
final class Schema
{
    use HasLogger;

    /**
     * Schema version. Bump on any change to a CREATE TABLE below.
     *
     * 1 — devices, messages and message recipients.
     * 2 — password credentials, for members who set one.
     * 3 — recipients.received_at, for delivery receipts.
     * 4 — no table change: drops the retired Link logging settings from
     *     the settings rows (see Settings::dropRetired()). This is the one
     *     hook an existing site runs on update, so it is where a one-off
     *     clean-up has to live.
     * 5 — the old Link tables (devices, messages, message recipients) are no
     *     longer created, and the retired `link_backend` setting is dropped.
     *     Link signs in and sends through Firebase.
     */
    public const VERSION = 5;

    public const OPTION = 'fellowship_schema_version';

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * Create or upgrade every table if the stored version is behind.
     *
     * Cheap on the common path: one option read and nothing else. Safe
     * to call on every request, and called from {@see \Fellowship\Plugin::init()}
     * so an updated site repairs itself on its next page load rather than
     * waiting for someone to think of reactivating the plugin.
     */
    public static function ensureInstalled(): void
    {
        $installed = (int) get_option(self::OPTION, 0);
        if ($installed >= self::VERSION) {
            return;
        }

        global $wpdb;

        // Guarded rather than assumed. This runs from Plugin::init(), and
        // a TypeError there would take the whole site down — a far worse
        // outcome than a schema install that waits for the next request.
        if (!$wpdb instanceof wpdb) {
            self::logWarning('Schema install skipped: $wpdb is not available yet');
            return;
        }

        self::install($wpdb);

        update_option(self::OPTION, self::VERSION, true);

        self::logInfo('Schema installed or upgraded', [
            'from' => $installed,
            'to'   => self::VERSION,
        ]);
    }

    /**
     * Record the schema as current without running the installers.
     *
     * For the activation hook, which has just called {@see install()}
     * directly. Without this the option would still say "behind" and the
     * next page load would run every dbDelta again — harmless, since they
     * are idempotent, but a pointless round of queries on the one request
     * that has certainly just done them.
     */
    public static function markInstalled(): void
    {
        update_option(self::OPTION, self::VERSION, true);
    }

    /**
     * Run every table's installer. Each is an idempotent dbDelta, so this
     * is safe to call repeatedly and is what the activation hook uses too.
     */
    public static function install(wpdb $wpdb): void
    {
        // Fellowship creates no tables of its own any more. Link's devices and
        // messages live in Firestore, and password credentials are Unity's,
        // installed on its own version change. See
        // Unity\Auth\WpdbPasswordCredentialRepository.
        Settings::dropRetired();
    }
}
