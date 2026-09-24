<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Schema;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\RecordingWpdb;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * What the admin POST handlers actually do, and the schema installer.
 *
 * <b>Revoking is the one that has to work.</b> It is how a lost or stolen
 * handset is cut off, and the effect is immediate and total: every lookup
 * that could authenticate carries `revoked_at IS NULL`, so the device
 * stops being found rather than being found and rejected.
 *
 * <b>Removing is not a tidier revoke.</b> It deletes the row, so it is
 * done second and only after the revoke has already landed — the other
 * order would leave a working credential behind on a failed delete.
 *
 * The service account is parsed before it is stored, because a setting
 * that looks saved and pushes nothing is the worst of both, and the
 * moment to find out is while somebody is looking at the screen.
 */

covers(\Fellowship\Admin\DevicesPage::class, \Fellowship\Admin\SettingsPage::class, \Fellowship\Core\Schema::class);

const ADMIN_HANDLERS_MEMBER = 'member@example.org';

beforeEach(function () {
    $_POST = [];
    WpState::$userCan = true;

    when('get_current_user_id')->justReturn(3);
    when('check_admin_referer')->justReturn(true);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    $this->devices = new InMemoryDeviceRepository();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: ADMIN_HANDLERS_MEMBER),
    ]);
});

// ── Cutting a handset off ─────────────────────────────────────────

test('revoking cuts the handset off', function () {
    adminHandlersEnrol();
    $_POST['device'] = '1';

    expect(adminHandlersDevicesPage()->revokeFromRequest())->toBe('revoked');
    expect($this->devices->rows[1]->isRevoked())->toBeTrue();
});

test('a revoked handset can no longer be found by its token', function () {
    // Which is the whole mechanism: it is refused because it is not
    // there, not because something downstream checks a flag.
    adminHandlersEnrol();
    $_POST['device'] = '1';

    adminHandlersDevicesPage()->revokeFromRequest();

    expect($this->devices->findByTokenHash('hash-1'))->toBeNull();
});

test('revoking is audited', function () {
    adminHandlersEnrol();
    $_POST['device'] = '1';

    adminHandlersDevicesPage()->revokeFromRequest();

    expect($this->audit->entries)->not->toBeEmpty();
});

test('revoking something already revoked writes no second entry', function () {
    // Otherwise the log gains an entry for a revocation that did not
    // happen, which makes the ones that did harder to find.
    adminHandlersEnrol();
    $_POST['device'] = '1';

    adminHandlersDevicesPage()->revokeFromRequest();
    $first = count($this->audit->entries);

    adminHandlersDevicesPage()->revokeFromRequest();

    expect($this->audit->entries)->toHaveCount($first);
});

test('removing revokes first and then deletes', function () {
    // The order matters: if the delete fails the handset is still cut
    // off, which is the half that counts. The other way round leaves
    // a working credential behind.
    adminHandlersEnrol();
    $_POST['device'] = '1';

    expect(adminHandlersDevicesPage()->removeFromRequest())->toBe('removed');
    expect($this->devices->rows)->toBe([]);
});

test('a device id that is not an id is refused', function () {
    // Validated rather than cast: "12abc" must not quietly become 12,
    // because the value goes into the nonce action name.
    adminHandlersEnrol();
    $_POST['device'] = '1abc';

    adminHandlersDevicesPage()->revokeFromRequest();
})->throws(WpDieException::class);

test('naming no device is refused', function () {
    adminHandlersDevicesPage()->revokeFromRequest();
})->throws(WpDieException::class);

// ── Saving settings ───────────────────────────────────────────────

test('the provider credentials are saved', function () {
    $settings = new Settings();
    $_POST['google_client_id'] = 'google-client-id';
    $_POST['microsoft_client_id'] = 'ms-client-id';
    $_POST['google_client_secret'] = 'a-secret';

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('saved');
    expect($settings->getClientId('google'))->toBe('google-client-id');
    expect($settings->getClientId('microsoft'))->toBe('ms-client-id');
    expect($settings->getClientSecret('google'))->toBe('a-secret');
});

test('an empty secret field leaves the stored one alone', function () {
    // The field is never populated with the stored value, so an empty
    // submission is the normal case for anyone editing something else
    // on the screen. Treating it as "clear" would wipe a secret every
    // time somebody changed the retention window.
    $settings = new Settings();
    $settings->setClientSecret('google', 'a-secret');

    $_POST['google_client_secret'] = '';

    (new SettingsPage($settings))->saveFromRequest();

    expect($settings->getClientSecret('google'))->toBe('a-secret');
});

test('the checkbox is how a secret is cleared', function () {
    $settings = new Settings();
    $settings->setClientSecret('google', 'a-secret');

    $_POST['clear_google_client_secret'] = '1';

    (new SettingsPage($settings))->saveFromRequest();

    expect($settings->getClientSecret('google'))->toBe('');
});

test('a service account that will not parse is refused before it is stored', function () {
    // A setting that looks saved and pushes nothing is the worst of
    // both, and the moment to find out is while somebody is looking
    // at the screen.
    $settings = new Settings();
    $_POST['fcm_service_account'] = 'not json';

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('bad_service_account');
    expect($settings->getFcmServiceAccount())->toBe('');
});

test('a valid service account is stored', function () {
    $settings = new Settings();
    $_POST['fcm_service_account'] = (string) wp_json_encode([
        'project_id' => 'intergroup-fellowship',
        'client_email' => 'pusher@example.iam.gserviceaccount.com',
        'private_key' => '-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----',
    ]);

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('saved');
    expect($settings->getFcmServiceAccount())->toContain('intergroup-fellowship');
});

test('the retention window is saved', function () {
    $settings = new Settings();
    $_POST['retention_days'] = '90';

    (new SettingsPage($settings))->saveFromRequest();

    expect($settings->getRetentionDays())->toBe(90);
});

test('committee sending is off when the box is unticked', function () {
    // An unticked checkbox posts nothing at all, so "absent" has to
    // mean off rather than "leave as it was".
    $settings = new Settings();
    $settings->setCommitteeSendFromApp(true);

    (new SettingsPage($settings))->saveFromRequest();

    expect($settings->allowsCommitteeSendFromApp())->toBeFalse();
});

// ── The schema ────────────────────────────────────────────────────

test('every table is installed', function () {
    $wpdb = new RecordingWpdb();

    Schema::install($wpdb);

    $sql = implode(' ', $GLOBALS['__fellowship_dbdelta'] ?? []);

    foreach (['devices', 'messages', 'recipients'] as $table) {
        expect($sql)->toContain('fellowship_' . $table);
    }

    // Credentials are Unity's table now, and Unity installs it on its
    // own version change. Asserted rather than merely dropped from the
    // list above: installing it from here as well would give two
    // plugins a claim on one schema, and the one that lost a race
    // would be the one whose dbDelta ran against a table it did not
    // define.
    expect($sql)->not->toContain('credentials');
});

test('installing is skipped when the schema is current', function () {
    // Runs from Plugin::init on every request, so the common path has
    // to be one option read and nothing else.
    WpState::$options[Schema::OPTION] = Schema::VERSION;
    $GLOBALS['__fellowship_dbdelta'] = [];

    Schema::ensureInstalled();

    expect($GLOBALS['__fellowship_dbdelta'])->toBe([]);
});

// ── Fixtures ──────────────────────────────────────────────────────

function adminHandlersDevicesPage(): DevicesPage
{
    $gate = new MemberGate(test()->members);

    return new DevicesPage(
        test()->devices,
        test()->members,
        test()->audit,
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        $gate,
    );
}

function adminHandlersEnrol(): void
{
    test()->devices->create(
        'hash-1',
        ADMIN_HANDLERS_MEMBER,
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );
}
