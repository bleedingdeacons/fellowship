<?php

/**
 * Plugin Name: Fellowship
 * Description: Server side of the Link messaging app. Enrols Android and iOS handsets against Unity members by OAuth-verified email, exchanges a device public key at enrolment, and delivers messages to individuals and committees as encrypted push notifications. Requires Unity and Scrutiny.
 * Version: 1.0.0
 * Requires at least: 6.1
 * Requires PHP: 8.1
 * Requires Plugins: unity, scrutiny
 * GitHub Plugin URI: https://github.com/bleedingdeacons/fellowship
 * GitHub Branch: main
 * Author: The Bleeding Deacons
 * Author URI: https://github.com/bleedingdeacons/fellowship
 * Contact: thebleedingdeacons@gmail.com
 * Text Domain: fellowship
 * License: MIT (Modified)
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('get_plugin_data')) {
    if (file_exists(ABSPATH . 'wp-admin/includes/plugin.php')) {
        require_once(ABSPATH . 'wp-admin/includes/plugin.php');
    }
}

$fellowship_plugin_data = get_plugin_data(__FILE__, false, false);
define('FELLOWSHIP_VERSION', $fellowship_plugin_data['Version']);
define('FELLOWSHIP_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FELLOWSHIP_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FELLOWSHIP_PLUGIN_FILE', __FILE__);

// Autoloader for the Fellowship namespace.
spl_autoload_register(function ($class) {
    try {
        $prefix = 'Fellowship\\';
        $base_dir = FELLOWSHIP_PLUGIN_DIR . 'src/';

        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            return;
        }

        $relative_class = substr($class, $len);
        $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

        if (file_exists($file)) {
            require $file;
        }
    } catch (\Exception $e) {
        function_exists('wp_log')
            ? wp_log('fellowship')->error('Fellowship Autoloader Error: ' . $e->getMessage(), ['exception' => $e->getMessage(), 'trace' => $e->getTraceAsString()])
            : error_log('Fellowship Autoloader Error: ' . $e->getMessage());
    } catch (\Throwable $e) {
        function_exists('wp_log')
            ? wp_log('fellowship')->critical('Fellowship Autoloader Fatal Error: ' . $e->getMessage(), ['exception' => $e->getMessage(), 'trace' => $e->getTraceAsString()])
            : error_log('Fellowship Autoloader Fatal Error: ' . $e->getMessage());
    }
});

/**
 * Get the Fellowship dependency container (Unity's container).
 *
 * @return \Psr\Container\ContainerInterface
 * @throws \RuntimeException If Fellowship is not initialised
 */
function fellowship(): \Psr\Container\ContainerInterface
{
    return \Fellowship\Plugin::getContainer();
}

/**
 * Send a message to Link handsets.
 *
 * The supported way for another plugin to put a message in front of
 * members:
 *
 *     $id = fellowship_send_message([
 *         'subject'   => 'Intergroup meeting moved',
 *         'body'      => 'September intergroup is now the 14th.',
 *         'committee' => 'public-information',
 *     ]);
 *
 * Address it with `committee` (slug or id), `member_emails` (a list), or
 * neither for every enrolled member. `subject` and `body` are required.
 *
 * Unlike Reach's alerting API this one is not lock-screen constrained.
 * Message bodies are sealed to each handset's own public key and never
 * travel in a notification's visible text; what reaches the tray before
 * the app decrypts is "New message", nothing more. That is why a message
 * may carry ordinary fellowship business where an alert may not.
 *
 * Guarded so a caller can use `function_exists('fellowship_send_message')`
 * to degrade gracefully when Fellowship is not installed.
 *
 * @param array<string, mixed> $message
 * @return int|\WP_Error The stored message id, or why it was refused.
 */
if (!function_exists('fellowship_send_message')) {
    function fellowship_send_message(array $message): int|\WP_Error
    {
        try {
            return \Fellowship\Plugin::getContainer()
                ->get(\Fellowship\Messaging\MessageApi::class)
                ->send($message);
        } catch (\Throwable $e) {
            // Fellowship not initialised yet, or its container could not
            // build the API. A caller reaching for this before
            // 'fellowship/loaded' gets a WP_Error rather than a fatal: a
            // message that could not be sent must never take the calling
            // plugin down with it.
            return new \WP_Error(
                'fellowship_unavailable',
                'Fellowship is not ready to accept messages: ' . $e->getMessage(),
                ['status' => 503],
            );
        }
    }
}

// Initialise after Unity is loaded.
add_action('unity/loaded', function ($container) {
    try {
        // The kill switch stands Fellowship down without deactivating it:
        // no routes, no admin pages, no push. Set FELLOWSHIP_KILL in
        // wp-config.php.
        //
        // Enrolled handsets are deliberately left alone. Nothing
        // authenticates while the routes are unregistered anyway, and
        // revoking every device would force the whole fellowship to
        // re-enrol over what is meant to be a temporary stand-down.
        if (defined('FELLOWSHIP_KILL') && FELLOWSHIP_KILL) {
            return;
        }

        // Scrutiny provides the AuditLogger that records every exposure
        // of an address-book entry and every message sent. Without it
        // Fellowship would silently lose its audit trail — fail loud at
        // init time instead.
        if (!function_exists('scrutiny')) {
            throw new \Exception('Scrutiny plugin is required but not active. Please install and activate Scrutiny before using Fellowship.');
        }

        if (!class_exists('Fellowship\Plugin')) {
            throw new \Exception('Fellowship\Plugin class not found.');
        }

        \Fellowship\Plugin::init($container);

        do_action('fellowship/loaded', \Fellowship\Plugin::getContainer());
    } catch (\Exception $e) {
        function_exists('wp_log')
            ? wp_log('fellowship')->error('Fellowship Plugin Initialization Error: ' . $e->getMessage(), ['exception' => $e->getMessage(), 'trace' => $e->getTraceAsString()])
            : error_log('Fellowship Plugin Initialization Error: ' . $e->getMessage());

        if (is_admin()) {
            add_action('admin_notices', function () use ($e) {
                echo '<div class="notice notice-error is-dismissible"><p><strong>Fellowship Plugin Error:</strong> ' . esc_html($e->getMessage()) . '</p></div>';
            });
        }
    } catch (\Throwable $e) {
        function_exists('wp_log')
            ? wp_log('fellowship')->critical('Fellowship Plugin Fatal Error: ' . $e->getMessage(), ['exception' => $e->getMessage(), 'trace' => $e->getTraceAsString()])
            : error_log('Fellowship Plugin Fatal Error: ' . $e->getMessage());
    }
}, 10);

// Show an admin notice if a required plugin is not available.
add_action('plugins_loaded', function () {
    if (!class_exists('Unity\\Plugin')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>';
            echo '<strong>' . esc_html__('Fellowship', 'fellowship') . ':</strong> ';
            echo esc_html__('This plugin requires the Unity plugin to be installed and activated.', 'fellowship');
            echo '</p></div>';
        });
    } elseif (!function_exists('scrutiny')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>';
            echo '<strong>' . esc_html__('Fellowship', 'fellowship') . ':</strong> ';
            echo esc_html__('This plugin requires the Scrutiny plugin to be installed and activated for GDPR audit logging.', 'fellowship');
            echo '</p></div>';
        });
    }
}, 20);

// Activation: ensure Unity and Scrutiny are present, and install tables.
register_activation_hook(__FILE__, function () {
    if (!function_exists('scrutiny')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(
            esc_html__('Fellowship requires the Unity and Scrutiny plugins to be installed and activated. Scrutiny must be active to ensure GDPR audit logging of message delivery.', 'fellowship'),
            esc_html__('Plugin Activation Error', 'fellowship'),
            ['back_link' => true]
        );
    }

    // Every table. Schema owns the list and each installer is an
    // idempotent dbDelta, so this is safe on every activation including
    // upgrades. Activation is not the only path that creates tables —
    // see Fellowship\Core\Schema, which also runs on load when the
    // stored version is behind, because an update over an active plugin
    // never fires this hook at all.
    global $wpdb;
    \Fellowship\Core\Schema::install($wpdb);
    \Fellowship\Core\Schema::markInstalled();

    \Fellowship\Core\Capabilities::ensureAssigned();
});

// Self-deactivate if Scrutiny is deactivated while Fellowship is active —
// Fellowship can't honour its audit-logging promise without Scrutiny.
add_action('admin_init', function () {
    if (is_plugin_active(plugin_basename(__FILE__)) && !function_exists('scrutiny')) {
        deactivate_plugins(plugin_basename(__FILE__));
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p><strong>Fellowship has been deactivated:</strong> The Scrutiny plugin is required for GDPR audit logging but is not active.</p></div>';
        });
    }
});

register_deactivation_hook(__FILE__, function () {
    // Stop the retention sweep once Fellowship is inactive. Enrolled
    // handsets are left alone, for the reason the kill switch gives.
    wp_clear_scheduled_hook(\Fellowship\Plugin::PURGE_CRON_HOOK);
});
