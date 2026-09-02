<?php

declare(strict_types=1);

/**
 * Test bootstrap for Fellowship.
 *
 * WordPress stand-ins come from bleedingdeacons/wp-mocks, shared across
 * the plugin suite. Its bootstrap loads Patchwork before anything
 * patchable, so anything below that defines WordPress functions of its
 * own — here, only dbDelta() — must stay after the Bootstrap::load()
 * call, not before it.
 *
 * Groups: `wordpress`, plus `rest` because the controller tests drive
 * route callbacks with WP_REST_Request/WP_REST_Response, plus `sentinel`
 * so HasLogger's resolution path runs rather than being skipped by its
 * function_exists('wp_log') guard. Not `acf` — Fellowship does not use
 * it directly.
 */

use BleedingDeacons\WpMocks\Bootstrap;
use BleedingDeacons\WpMocks\WpState;

$autoloader = dirname(__DIR__) . '/vendor/autoload.php';
if (is_file($autoloader)) {
    require_once $autoloader;
}

Bootstrap::load(['wordpress', 'rest', 'sentinel']);

WpState::$pluginSlug = 'fellowship';

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

// Normally set by fellowship.php from plugin_dir_path(__FILE__), which is
// not loaded here.
if (!defined('FELLOWSHIP_PLUGIN_DIR')) {
    define('FELLOWSHIP_PLUGIN_DIR', dirname(__DIR__) . '/');
}
if (!defined('FELLOWSHIP_PLUGIN_FILE')) {
    define('FELLOWSHIP_PLUGIN_FILE', dirname(__DIR__) . '/fellowship.php');
}

// Fellowship autoloader.
spl_autoload_register(function ($class) {
    $prefix = 'Fellowship\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/../src/' . str_replace('\\', '/', $relative) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

// Unity. The resolver, the controllers and several admin classes
// type-hint Unity\Members\Interfaces\{Member, MemberRepository},
// Unity\Committees\Interfaces\CommitteeRepository and
// Unity\Core\Interfaces\Container, and the fixtures extend the test
// doubles Unity ships at Unity\Testing\Doubles. A PSR-4 autoloader over
// the sibling checkout covers all of it; UNITY_PATH overrides the
// default location.
//
// Deliberately no eval()'d fallback copy of those interfaces. A copy of
// a contract owned elsewhere, never exercised in CI (which always checks
// Unity out), is how a suite goes green against a contract that has
// since moved.
$unityPath = getenv('UNITY_PATH') ?: dirname(__DIR__, 2) . '/unity';
$unitySrc  = $unityPath . '/src';

if (!is_dir($unitySrc)) {
    fwrite(STDERR, PHP_EOL . 'ERROR: Unity plugin source not found at ' . $unitySrc . PHP_EOL
        . "Fellowship is built on Unity's interfaces and test doubles, so the Unity" . PHP_EOL
        . 'plugin must be checked out as a sibling directory (or UNITY_PATH set) for' . PHP_EOL
        . 'this suite to run.' . PHP_EOL . PHP_EOL);
    exit(1);
}

spl_autoload_register(static function (string $class) use ($unitySrc): void {
    if (!str_starts_with($class, 'Unity' . chr(92))) {
        return;
    }

    $file = $unitySrc . '/' . str_replace(chr(92), '/', substr($class, strlen('Unity' . chr(92)))) . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});

// Scrutiny. The controllers type-hint Scrutiny\Audit\Interfaces\AuditLogger
// and read constants off Scrutiny\Privacy\PersonalDataPolicy, and the
// tests audit through the spy Scrutiny ships at Scrutiny\Testing\Doubles.
$scrutinyPath = getenv('SCRUTINY_PATH') ?: dirname(__DIR__, 2) . '/scrutiny';
$scrutinySrc  = $scrutinyPath . '/src';

if (!is_dir($scrutinySrc)) {
    fwrite(STDERR, PHP_EOL . 'ERROR: Scrutiny plugin source not found at ' . $scrutinySrc . PHP_EOL
        . "Fellowship is built on Scrutiny's audit contract and test doubles, so the" . PHP_EOL
        . 'Scrutiny plugin must be checked out as a sibling directory (or' . PHP_EOL
        . 'SCRUTINY_PATH set) for this suite to run.' . PHP_EOL . PHP_EOL);
    exit(1);
}

spl_autoload_register(static function (string $class) use ($scrutinySrc): void {
    if (!str_starts_with($class, 'Scrutiny' . chr(92))) {
        return;
    }

    $file = $scrutinySrc . '/'
        . str_replace(chr(92), '/', substr($class, strlen('Scrutiny' . chr(92)))) . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});

// dbDelta() lives in wp-admin/includes rather than the loaded core, so no
// shared stub group covers it. The Wpdb repositories call it from their
// install() routines, and the tests only need to confirm install()
// reaches it without touching a database — so record the SQL and return.
$GLOBALS['__fellowship_dbdelta'] = [];
if (!function_exists('dbDelta')) {
    function dbDelta($queries = '', bool $execute = true): array
    {
        $GLOBALS['__fellowship_dbdelta'][] = $queries;

        return [];
    }
}
