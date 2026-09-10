<?php

/**
 * The WP-CLI symbols this plugin uses, for static analysis only.
 *
 * <b>Why this is not php-stubs/wp-cli-stubs.</b> That package is what
 * Concordance uses, and it was the first thing tried here. Every published
 * version of it — 2.12.0 down to 2.7.0 — requires
 * `php-stubs/wordpress-stubs ^4.7 || ^5.0 || ^6.0`, and this plugin is on
 * v7.1.0. Composer refuses the combination outright. Taking the package
 * would mean pinning WordPress's own stubs a major version back, for every
 * file in `src/`, to describe one class and two functions.
 *
 * So the symbols actually called are declared here instead. Listed in
 * `phpstan.neon.dist` under `scanFiles`, and never loaded at runtime:
 * WP-CLI defines the real ones, and `Plugin::init()` only touches them
 * behind `defined('WP_CLI')`. There is deliberately no ABSPATH guard —
 * nothing includes this file.
 *
 * Bracketed namespaces because the helpers live under `WP_CLI\Utils` while
 * the classes are global, and a file cannot open a second namespace after
 * unbracketed code.
 *
 * Keep it minimal. It exists to stop PHPStan reporting a real command as
 * an unknown class, not to model WP-CLI — anything here the plugin does
 * not call is a description nobody checks.
 */

namespace {
    class WP_CLI
    {
        /**
         * @param string          $name     The command, e.g. "fellowship directory".
         * @param callable|object $callable The command's implementation.
         * @param array<string, mixed> $args
         */
        public static function add_command($name, $callable, $args = []): bool
        {
            return true;
        }

        /** @param string $message */
        public static function log($message): void
        {
        }

        /** @param string $message */
        public static function warning($message): void
        {
        }
    }

    class WP_CLI_Command
    {
    }
}

namespace WP_CLI\Utils {
    /**
     * @param array<string, mixed> $assoc_args
     * @param string               $flag
     * @param mixed                $default
     *
     * @return mixed
     */
    function get_flag_value($assoc_args, $flag, $default = null)
    {
        return $default;
    }

    /**
     * @param string                           $format
     * @param array<int, array<string, mixed>> $items
     * @param array<int, string>|string        $fields
     */
    function format_items($format, $items, $fields): string
    {
        return '';
    }
}
