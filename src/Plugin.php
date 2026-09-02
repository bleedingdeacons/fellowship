<?php

declare(strict_types=1);

namespace Fellowship;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Core\Capabilities;
use Fellowship\Core\FellowshipServiceProvider;
use Fellowship\Core\Schema;
use Fellowship\Core\Settings;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Logger\HasLogger;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Rest\DirectoryController;
use Fellowship\Rest\MessageController;
use Psr\Container\ContainerInterface;
use RuntimeException;
use Unity\Core\Interfaces\Container;

use function add_action;
use function add_filter;
use function is_admin;

/**
 * Wires Fellowship together.
 *
 * Registers services into Unity's container, registers the three REST
 * controllers and the admin screens, and schedules the retention sweep.
 */
final class Plugin
{
    use HasLogger;

    /** Daily sweep that deletes messages past the retention window. */
    public const PURGE_CRON_HOOK = 'fellowship_purge_messages';

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    private static ?ContainerInterface $container = null;
    private static bool $initialized = false;

    /**
     * Cached build date read from readme.txt. Null means "not looked up
     * yet"; the empty string is a valid cached result and stops us
     * re-reading the file on every render.
     */
    private static ?string $buildDate = null;

    public static function init(Container $unityContainer): void
    {
        if (self::$initialized) {
            return;
        }

        self::$container = $unityContainer;

        // Held locally as well as statically. The static property is
        // nullable — it has to be, nothing else can say "not
        // initialised yet" — and calling anything in between widens it
        // back to that, so every get() below would otherwise have to be
        // guarded against a null that cannot happen here.
        $container = $unityContainer;

        // Create or upgrade tables before anything can query them. The
        // activation hook is not enough on its own — see Core\Schema.
        Schema::ensureInstalled();

        // Likewise granted on load rather than only at activation: an
        // update over an active plugin never fires the activation hook,
        // so a capability introduced in a release would otherwise never
        // reach an existing site.
        Capabilities::ensureAssigned();

        (new FellowshipServiceProvider())->register($unityContainer);

        self::$initialized = true;

        $container->get(DeviceAuthController::class)->register();
        $container->get(MessageController::class)->register();
        $container->get(DirectoryController::class)->register();

        // The action form of the sending API. The function form
        // (fellowship_send_message) needs no registration — it is
        // declared in the plugin bootstrap and resolves through the
        // container when called.
        $container->get(MessageApi::class)->register();

        self::registerPurge();

        // Everything under fellowship/v1 is per-device and authorised by
        // a bearer token, which shared caches (SiteGround, Cloudflare,
        // the browser) do not recognise. WordPress only sends REST
        // no-cache headers for logged-in WP users, so a member's sealed
        // inbox could otherwise be cached and served to the next caller.
        // Force no-store across the namespace.
        add_filter('rest_post_dispatch', static function ($response, $server, $request) {
            if (
                $response instanceof \WP_REST_Response
                && $request instanceof \WP_REST_Request
                && str_starts_with(ltrim((string) $request->get_route(), '/'), DeviceAuthController::NAMESPACE)
            ) {
                $response->header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0, private');
            }

            return $response;
        }, 10, 3);

        self::registerErasure();

        if (is_admin()) {
            // Order matters: MessagesPage registers the top-level
            // "Fellowship" menu and the others attach to its slug. Both
            // use the same admin_menu hook, so callbacks fire in
            // registration order — a submenu registered before its parent
            // exists silently falls back to a URL that goes nowhere.
            $container->get(MessagesPage::class)->register();
            $container->get(ComposePage::class)->register();
            $container->get(DevicesPage::class)->register();
            $container->get(SettingsPage::class)->register();
        }

        self::logDebug('Initialised', [
            'version' => defined('FELLOWSHIP_VERSION') ? FELLOWSHIP_VERSION : 'unknown',
        ]);
    }

    public static function getContainer(): ContainerInterface
    {
        if (self::$container === null) {
            throw new RuntimeException('Fellowship Plugin not initialized');
        }

        return self::$container;
    }

    /**
     * Daily deletion of messages past the retention window.
     *
     * Scheduled here rather than on activation so an install upgraded
     * into this version picks it up on its next load without being
     * reactivated.
     */
    private static function registerPurge(): void
    {
        if (!wp_next_scheduled(self::PURGE_CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PURGE_CRON_HOOK);
        }

        add_action(self::PURGE_CRON_HOOK, static function (): void {
            $container = self::$container;
            if ($container === null) {
                return;
            }

            $days = $container->get(Settings::class)->getRetentionDays();
            if ($days <= 0) {
                // Zero means keep indefinitely — a deliberate choice, made
                // on the settings screen. Nothing to do.
                return;
            }

            $before = time() - ($days * DAY_IN_SECONDS);

            // Recipients first: they are found by joining to the messages,
            // so deleting the messages first would strand every recipient
            // row against an id that no longer exists — and a stranded row
            // here is orphaned personal data, which is the one kind this
            // stack must not leave lying about.
            $recipients = $container->get(RecipientRepository::class)->purgeForMessagesBefore($before);
            $messages   = $container->get(MessageRepository::class)->purgeBefore($before);

            if ($messages > 0 || $recipients > 0) {
                self::logInfo('Retention sweep completed', [
                    'messages'   => $messages,
                    'recipients' => $recipients,
                    'days'       => $days,
                ]);
            }
        });
    }

    /**
     * GDPR erasure: when Unity deletes a member, take their handsets and
     * their delivery records with them.
     *
     * The devices would fail their next request anyway — CurrentDevice
     * re-runs the gate on every call — but that leaves live rows the
     * dispatcher still counts as push targets in the meantime, and a
     * message briefly addressed to somebody who has been removed is
     * exactly what the gate exists to prevent.
     *
     * Message *bodies* are deliberately not deleted here. A message sent
     * to a committee is a record of what the intergroup said, not of who
     * received it, and removing one member should not rewrite it. The
     * recipient rows naming them do go, which is the part that is theirs.
     */
    private static function registerErasure(): void
    {
        $container = self::$container;
        if ($container === null) {
            return;
        }

        $devices = $container->get(DeviceRepository::class);
        $recipients = $container->get(RecipientRepository::class);

        add_action('unity/member_deleted', static function ($postId, $member = null) use ($devices, $recipients): void {
            if ($member === null) {
                return;
            }

            $email = strtolower(trim((string) $member->getPersonalEmail()));
            if ($email === '') {
                return;
            }

            $revoked = $devices->revokeAllForMember($email, time());
            $removed = $recipients->deleteForMember($email);

            self::logInfo('Member deleted: handsets revoked and delivery records removed', [
                'devices'    => $revoked,
                'recipients' => $removed,
            ]);
        }, 10, 2);
    }

    /**
     * The build date stamped into readme.txt by the build script, e.g.
     * "2026/09/01 13:45:36". Empty string when there is no Build date
     * line — for instance running straight from a working checkout.
     */
    public static function buildDate(): string
    {
        if (self::$buildDate === null) {
            $dir = defined('FELLOWSHIP_PLUGIN_DIR') ? FELLOWSHIP_PLUGIN_DIR : __DIR__ . '/../';
            self::$buildDate = self::readBuildDateFromReadme($dir);
        }

        return self::$buildDate;
    }

    private static function readBuildDateFromReadme(string $pluginDir): string
    {
        foreach (['readme.txt', 'README.txt'] as $name) {
            $readme = rtrim($pluginDir, '/\\') . '/' . $name;
            if (!is_readable($readme)) {
                continue;
            }

            // The build date lives in the header block at the top of the
            // file; read only the first chunk rather than loading it all.
            $contents = file_get_contents($readme, false, null, 0, 8192);
            if ($contents === false) {
                continue;
            }

            if (preg_match('/^[ \t]*Build date[ \t]*:[ \t]*(.+?)[ \t]*$/mi', $contents, $matches)) {
                return trim($matches[1]);
            }
        }

        return '';
    }
}
