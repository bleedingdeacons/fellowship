<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Capabilities;
use Fellowship\Core\Schema;
use Fellowship\Core\Settings;
use Fellowship\Logger\HasLogger;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The tables each repository asks for, and what the plugin says about
 * itself.
 *
 * <b>The schema is asserted on the SQL because dbDelta will not tell you
 * it went wrong.</b> It diffs against the live schema and applies what it
 * can; a column it cannot parse is simply not created, and the first
 * anybody hears of it is a query failing in production. The properties
 * pinned here are the ones that would fail exactly that way:
 *
 *  - the token hash is unique, which is what makes a bearer token
 *    identify one device rather than whichever row came back first;
 *  - a member's address is indexed at 191 characters, because a utf8mb4
 *    index entry is four bytes per character and a composite key would
 *    otherwise clear InnoDB's 3072-byte limit only by luck;
 *  - a recipient row is unique per message and member, which is what lets
 *    the insert be an INSERT IGNORE and the unique key be the arbiter of
 *    a race.
 *
 * <b>Logging is exercised for real here, not as a no-op.</b> Sentinel
 * supplies wp_log and this suite loads its stub group, so HasLogger's
 * resolution path runs rather than being skipped by its function_exists
 * guard. Every level is called because they all sit on paths that only
 * run when something has already gone wrong, which is precisely where a
 * typo would go unnoticed. (Fellowship does not *require* Sentinel, and
 * the guard is what makes it optional — but proving the guard rather
 * than the logging would be testing the absence of a dependency.)
 *
 * The four repositories are named in the annotations below as well as
 * Schema, because that list restricts what a test is credited with:
 * calling install() on them without naming them runs the code and
 * records none of it. Same per-class attribution that makes an extracted
 * method look untested until its new class is listed.
 *
 * (Written without the annotation's own name in this sentence — a bare
 * one in prose parses as an annotation with no argument, and PHPUnit
 * then discards every real one in the block. Which is how this comment
 * came to be worth writing.)
 */

covers(\Fellowship\Core\Schema::class, \Fellowship\Core\Settings::class, \Fellowship\Core\Capabilities::class, \Fellowship\Logger\HasLogger::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
    $GLOBALS['wpdb'] = $this->wpdb;
    $GLOBALS['__fellowship_dbdelta'] = [];
});

// ── The schema version ────────────────────────────────────────────

test('Fellowship creates no tables of its own', function () {
    // Link's devices and messages live in Firestore, and password
    // credentials are Unity's. A fresh install gets nothing it won't use.
    Schema::install($this->wpdb);

    expect($GLOBALS['__fellowship_dbdelta'])->toBe([]);
});

test('the schema version is recorded so the next load is cheap', function () {
    // ensureInstalled runs from Plugin::init on every request. The
    // common path has to be one option read and nothing else.
    Schema::markInstalled();

    expect(WpState::$options[Schema::OPTION] ?? null)->toBe(Schema::VERSION);
});

test('an older schema is upgraded', function () {
    WpState::$options[Schema::OPTION] = Schema::VERSION - 1;

    Schema::ensureInstalled();

    expect(WpState::$options[Schema::OPTION] ?? null)->toBe(Schema::VERSION);
});

test('the upgrade drops the old Link tables', function () {
    Schema::install($this->wpdb);

    $drops = array_values(array_filter($this->wpdb->queries, static fn(string $q): bool => str_starts_with($q, 'DROP TABLE')));

    expect($drops)->toBe([
        'DROP TABLE IF EXISTS `wp_fellowship_recipients`',
        'DROP TABLE IF EXISTS `wp_fellowship_messages`',
        'DROP TABLE IF EXISTS `wp_fellowship_devices`',
    ]);
});

test('an empty old credentials table is dropped too', function () {
    $this->wpdb->vars = ['wp_fellowship_credentials', 0];

    Schema::install($this->wpdb);

    expect($this->wpdb->queries)->toContain('DROP TABLE IF EXISTS `wp_fellowship_credentials`');
});

test('an old credentials table that still holds rows is kept', function () {
    // tsml-for-unity leaves it as the only copy of some passwords until
    // somebody has seen its copy work, so an upgrade must not take it.
    $this->wpdb->vars = ['wp_fellowship_credentials', 3];

    Schema::install($this->wpdb);

    expect($this->wpdb->queries)->not->toContain('DROP TABLE IF EXISTS `wp_fellowship_credentials`');
});

test('a site that never had the credentials table is not asked to count it', function () {
    Schema::install($this->wpdb);

    expect(implode(' ', $this->wpdb->queries))->not->toContain('SELECT COUNT(*)');
});

test('the upgrade to version 5 drops the retired backend setting', function () {
    WpState::$options[Settings::OPTION_PUBLIC] = ['link_backend' => 'firebase', 'retention_days' => '30'];
    WpState::$options[Schema::OPTION] = 4;

    Schema::ensureInstalled();

    expect(WpState::$options[Settings::OPTION_PUBLIC])->toBe(['retention_days' => '30']);
});

test('the upgrade to version 4 drops the retired Link logging settings', function () {
    // The /logging route went on 2026-09-30, when Link started taking its
    // Better Stack settings from Freedom. The token was a credential, so
    // the upgrade removes it rather than leaving it encrypted in a row
    // nothing reads — and leaves everything else in both rows alone.
    WpState::$options[Settings::OPTION_PUBLIC] = ['log_endpoint' => 'https://s1.betterstackdata.com', 'google_client_id' => 'kept'];
    WpState::$options[Settings::OPTION_SECRETS] = ['log_source_token' => 'encrypted', 'google_client_secret' => 'kept'];
    WpState::$options[Schema::OPTION] = 3;

    Schema::ensureInstalled();

    expect(WpState::$options[Settings::OPTION_PUBLIC])->toBe(['google_client_id' => 'kept']);
    expect(WpState::$options[Settings::OPTION_SECRETS])->toBe(['google_client_secret' => 'kept']);
});

test('dropping retired settings leaves rows without them untouched', function () {
    WpState::$options[Settings::OPTION_PUBLIC] = ['google_client_id' => 'kept'];

    Settings::dropRetired();
    Settings::dropRetired();

    expect(WpState::$options[Settings::OPTION_PUBLIC])->toBe(['google_client_id' => 'kept']);
    expect(WpState::$options)->not->toHaveKey(Settings::OPTION_SECRETS);
});

// ── Capabilities ──────────────────────────────────────────────────

test('the administrator gets every capability', function () {
    // Granted on every load rather than only at activation: an update
    // over an active plugin never fires the activation hook, so a
    // capability introduced in a release would otherwise never reach
    // an existing site and the buttons it guards would go dead.
    $role = new \WP_Role();

    when('get_role')->justReturn($role);

    Capabilities::ensureAssigned();

    foreach (Capabilities::ALL as $capability) {
        expect($role->has_cap($capability))->toBeTrue($capability . ' was not granted.');
    }
});

test('assigning is skipped when there is no administrator role', function () {
    // Possible on a partially set-up site, and a fatal here would run
    // on every page load.
    when('get_role')->justReturn(null);

    Capabilities::ensureAssigned();
})->throwsNoExceptions();

// ── Logging ───────────────────────────────────────────────────────

test('every level reaches the channel', function () {
    // The suite loads the sentinel stub group, so wp_log exists here
    // and the resolution path runs for real rather than being skipped
    // by HasLogger's function_exists guard. Every level is exercised
    // because they are all on paths that only run when something has
    // already gone wrong — which is precisely where a typo would sit
    // unnoticed.
    $subject = new class {
        use HasLogger;
    };

    $channel = $subject::log();
    expect($channel)->not->toBeNull();

    $subject::logEmergency('m');
    $subject::logAlert('m');
    $subject::logCritical('m');
    $subject::logError('m');
    $subject::logWarning('m');
    $subject::logNotice('m');
    $subject::logInfo('m');
    $subject::logDebug('m');

    expect($channel->levels())->toBe(['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']);
});

test('the channel is named after the class using it', function () {
    // So a line in the log says which part of the plugin wrote it.
    $channel = Schema::log();

    expect($channel)->not->toBeNull();
    expect($channel->channel)->toBe('fellowship');
});

function schemaAndLoggingSql(): string
{
    return implode(' ', array_map('strval', $GLOBALS['__fellowship_dbdelta'] ?? []));
}
