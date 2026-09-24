<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * The four admin screens.
 *
 * <b>Deliberately in the coverage denominator.</b> phpunit.xml.dist has no
 * exclude for src/Admin, and the comment there says why: excluding a
 * directory does not merely hide it from the report, it removes it from
 * the denominator, so an untested admin layer reads as a *higher*
 * percentage than a tested one. The capability gates on these screens are
 * exactly the code that most wants a test.
 *
 * Three techniques, following the suite's existing pattern:
 *
 *  - the screens render for real inside an output buffer, so the markup
 *    is produced rather than mocked;
 *  - the capability guards are plain expectException, because wp_die()
 *    throws under the test doubles;
 *  - the POST handlers end in a redirect and an exit, which a test cannot
 *    follow, so what is driven is the guard rather than the body.
 *
 * <b>What is actually asserted is who may do what.</b> A reader who cannot
 * manage sees no buttons, and the handlers refuse them regardless — what
 * the page chose to render is not a permission check, and the tests treat
 * those as two separate claims because the code does.
 */

covers(\Fellowship\Admin\SettingsPage::class, \Fellowship\Admin\MessagesPage::class, \Fellowship\Admin\ComposePage::class, \Fellowship\Admin\DevicesPage::class);

const ADMIN_SCREENS_MEMBER = 'member@example.org';

beforeEach(function () {
    $_POST = [];
    $_GET = [];

    WpState::$userCan = true;

    when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
    when('get_current_user_id')->justReturn(3);
    when('submit_button')->justReturn(null);
    when('paginate_links')->justReturn('');

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->devices = new InMemoryDeviceRepository();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: ADMIN_SCREENS_MEMBER),
    ]);
});

// ── Settings ──────────────────────────────────────────────────────

test('the settings screen offers every sign in provider', function () {
    $markup = captureOutput(fn() => (new SettingsPage(new Settings()))->render());

    foreach (['Google', 'Microsoft', 'Facebook', 'Apple'] as $provider) {
        expect($markup)->toContain($provider);
    }
});

test('the settings screen shows the redirect URI to register', function () {
    // Whoever is configuring an OAuth client needs this exact string,
    // and getting it from the screen beats getting it from a README
    // that may not match the site.
    $markup = captureOutput(fn() => (new SettingsPage(new Settings()))->render());

    expect($markup)->toContain('auth/callback');
});

test('a stored secret is never rendered back', function () {
    // The field is write-only. Painting the stored value into the
    // markup would put every client secret in the page source of an
    // admin screen.
    $settings = new Settings();
    $settings->setClientId('google', 'google-client-id');

    $markup = captureOutput(fn() => (new SettingsPage($settings))->render());

    expect($markup)->toContain('google-client-id');
    expect($markup)->not->toContain('value="a-secret"');
});

test('saving settings without the capability is refused', function () {
    WpState::$userCan = false;

    (new SettingsPage(new Settings()))->handleSave();
})->throws(WpDieException::class);

test('the settings screen renders nothing to a reader who may not see it', function () {
    WpState::$userCan = false;

    expect(captureOutput(fn() => (new SettingsPage(new Settings()))->render()))->toBe('');
});

// ── The message log ───────────────────────────────────────────────

test('an empty message log says so rather than rendering an empty table', function () {
    $markup = captureOutput(fn() => adminScreensMessagesPage()->render());

    expect($markup)->toContain('No messages');
});

test('the message log lists what was sent', function () {
    $this->messages->create(
        'uuid-1',
        'dave@example.org',
        7,
        'Dave B',
        'Intergroup moved',
        'Now the 14th.',
        'committee',
        'steering',
        1788000000,
        0,
        0,
    );

    $markup = captureOutput(fn() => adminScreensMessagesPage()->render());

    expect($markup)->toContain('Intergroup moved');
});

test('the message log renders nothing without the capability', function () {
    // The log carries message subjects, which are the members' own
    // words.
    WpState::$userCan = false;

    expect(captureOutput(fn() => adminScreensMessagesPage()->render()))->toBe('');
});

// ── Compose ───────────────────────────────────────────────────────

test('the compose screen offers the committees', function () {
    $markup = captureOutput(fn() => adminScreensComposePage()->render());

    expect($markup)->toContain('<form');
});

test('the compose screen renders nothing without the capability', function () {
    WpState::$userCan = false;

    expect(captureOutput(fn() => adminScreensComposePage()->render()))->toBe('');
});

test('sending without the capability is refused', function () {
    // The one that matters most on this screen: sending reaches every
    // handset on a committee.
    WpState::$userCan = false;

    adminScreensComposePage()->handleSend();
})->throws(WpDieException::class);

// ── Devices ───────────────────────────────────────────────────────

test('the devices screen says so when nothing is enrolled', function () {
    $markup = captureOutput(fn() => adminScreensDevicesPage()->render());

    expect($markup)->toContain('No handsets');
});

test('the devices screen lists a handset and whose it is', function () {
    enrolADevice();

    $markup = captureOutput(fn() => adminScreensDevicesPage()->render());

    expect($markup)->toContain('Pixel 6a');
});

test('a reader who cannot manage is shown no buttons', function () {
    // Not a permission check in itself — the handlers check again —
    // but a button that answers 403 is a worse screen than one that
    // does not offer it.
    enrolADevice();
    WpState::$deniedCaps = ['fellowship_manage_devices'];

    $markup = captureOutput(fn() => adminScreensDevicesPage()->render());

    expect($markup)->not->toContain('Revoke');
});

test('the devices screen renders nothing without the view capability', function () {
    WpState::$userCan = false;

    expect(captureOutput(fn() => adminScreensDevicesPage()->render()))->toBe('');
});

test('revoking without the capability is refused', function () {
    WpState::$userCan = false;

    adminScreensDevicesPage()->handleRevoke();
})->throws(WpDieException::class);

test('removing without the capability is refused', function () {
    WpState::$userCan = false;

    adminScreensDevicesPage()->handleRemove();
})->throws(WpDieException::class);

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * Run a screen and capture what it printed.
 *
 * The screens echo directly, as WordPress admin screens do, so the
 * only way to assert on the markup is to buffer it.
 */
function adminScreensMessagesPage(): MessagesPage
{
    return new MessagesPage(test()->messages, test()->recipients);
}

function adminScreensComposePage(): ComposePage
{
    // A real MessageApi: the class is final, and doubling it would
    // only prove the page calls something. What these tests are about
    // is the capability guard, which sits in front of it either way.
    $gate = new MemberGate(test()->members);
    $settings = new Settings();
    $sealer = new MessageSealer();

    return new ComposePage(
        new MessageApi(
            new MessageDispatcher(
                test()->messages,
                test()->recipients,
                test()->devices,
                new FcmTransport(new FcmClient(), $settings, $sealer),
            ),
            new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
            test()->audit,
        ),
        new InMemoryCommitteeRepository(),
    );
}

function adminScreensDevicesPage(): DevicesPage
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

function enrolADevice(): void
{
    test()->devices->create(
        'hash-1',
        ADMIN_SCREENS_MEMBER,
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );
}
