<?php

declare(strict_types=1);

// Pest configuration.
//
// Tests that reach WordPress run on wp-mocks' TestCase, because Brain
// Monkey — add_action(), add_filter(), when() and the rest of the hook and
// stub layer — is only set up inside that TestCase's setUp() and torn down
// in its tearDown(). The pure-PHP tests — the JWT and provider crypto, the
// wire format, the device key and redirect rules, the request parsing and
// the PKCE store — need none of it and stay on Pest's default, plain
// PHPUnit, exactly as they extended PHPUnit's TestCase directly before.
//
// So this list is load-bearing. A test that reaches Brain Monkey from a
// file not named here finds none of its functions defined; a new
// WordPress-coupled test file has to be added to it.
//
// Every test file shares the Fellowship\Tests namespace, and Pest loads
// all of them before running any, so a file-level helper function or
// const is visible to — and collides with — every other file. That is why
// the helpers carry their file's name (adminBranchesEnrol(),
// ADMIN_BRANCHES_MEMBER) wherever the bare name was used by more than one
// file or was too generic to stay unique.

use BleedingDeacons\WpMocks\TestCase;

pest()->extend(TestCase::class)->in(
    'AdminBranchesTest.php',
    'AdminHandlersTest.php',
    'AdminNoticesTest.php',
    'AdminPasswordCodeTest.php',
    'AdminScreensTest.php',
    'AuditDetailTest.php',
    'ComposeSendTest.php',
    'ContainerWiringTest.php',
    'ControllerRoutesTest.php',
    'CoreUnitsTest.php',
    'DeviceAuthControllerTest.php',
    'DirectoryTest.php',
    'DispatcherTest.php',
    'EnrolmentEdgesTest.php',
    'FcmTokenTest.php',
    'InsecureAndLimitedTest.php',
    'MessageControllerTest.php',
    'MessageLogTest.php',
    'MessageSendTest.php',
    'MessageTableTest.php',
    'PasswordAuthenticatorTest.php',
    'PasswordFlowRestTest.php',
    'PluginBootstrapTest.php',
    'PushTest.php',
    'ReachedThroughTest.php',
    'RecipientResolverTest.php',
    'RecipientTableTest.php',
    'SchemaAndLoggingTest.php',
    'ServerSideProvidersTest.php',
    'SettingsTest.php',
    'TokenRefusalTest.php',
    'UserAgentTest.php',
    'WpdbDeviceRepositoryTest.php',
    'WpdbRepositoriesTest.php',
);

/**
 * Runs $render inside an output buffer and returns what it printed.
 *
 * The admin screens echo their markup, so this is how their tests read it.
 * The buffer is closed in a finally, so a render that throws — wp_die() is a
 * WpDieException under the shared stubs — cannot leave it open and have
 * PHPUnit flag the test as risky.
 */
function captureOutput(callable $render): string
{
    ob_start();

    try {
        $render();
    } finally {
        $html = (string) ob_get_clean();
    }

    return $html;
}
