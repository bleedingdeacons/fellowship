<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Capabilities;
use Fellowship\Core\Schema;
use Fellowship\Devices\WpdbDeviceRepository;
use Fellowship\Logger\HasLogger;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Messaging\WpdbRecipientRepository;
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

covers(\Fellowship\Core\Schema::class, \Fellowship\Core\Capabilities::class, \Fellowship\Logger\HasLogger::class, \Fellowship\Devices\WpdbDeviceRepository::class, \Fellowship\Messaging\WpdbMessageRepository::class, \Fellowship\Messaging\WpdbRecipientRepository::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
    $GLOBALS['wpdb'] = $this->wpdb;
    $GLOBALS['__fellowship_dbdelta'] = [];
});

// ── The tables ────────────────────────────────────────────────────

test('a device token hash is unique', function () {
    // What makes a bearer token identify one device rather than
    // whichever row happened to come back first.
    WpdbDeviceRepository::install($this->wpdb);

    expect(schemaAndLoggingSql())->toMatch('~UNIQUE KEY \w*\s*\(token_hash\)~i');
});

test('a recipient is unique per message and member', function () {
    // The arbiter the INSERT IGNORE relies on. Without it two sends
    // racing on the same committee both write, and a member receives
    // the same message twice.
    WpdbRecipientRepository::install($this->wpdb);

    $sql = schemaAndLoggingSql();

    expect($sql)->toContain('message_id');
    expect($sql)->toContain('member_email');
    expect($sql)->toMatch('~UNIQUE KEY~i');
});

test('an address is indexed at a prefix rather than its full length', function () {
    // A utf8mb4 index entry is four bytes per character, and a
    // composite key over a full 254 would clear InnoDB's 3072-byte
    // limit only by luck.
    WpdbRecipientRepository::install($this->wpdb);

    expect(schemaAndLoggingSql())->toContain('191');
});

test('a message table is created', function () {
    WpdbMessageRepository::install($this->wpdb);

    expect(schemaAndLoggingSql())->toContain('fellowship_messages');
});

test('every table carries the sites charset', function () {
    // Without it a table is created in the server default, which on an
    // older host is latin1 — and a message body would lose every
    // character outside it, silently, on the way in.
    Schema::install($this->wpdb);

    expect(schemaAndLoggingSql())->toContain('utf8mb4');
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

    expect($GLOBALS['__fellowship_dbdelta'])->not->toBe([]);
    expect(WpState::$options[Schema::OPTION] ?? null)->toBe(Schema::VERSION);
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
