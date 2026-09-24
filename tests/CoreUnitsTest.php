<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Brain\Monkey\Functions;
use function Brain\Monkey\Functions\when;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\Device;
use Fellowship\Devices\MemberGate;
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
 * The small classes everything else leans on.
 *
 * <b>Device::wantsPush is three conditions and all of them matter.</b> A
 * handset can claim the FCM transport and have no token yet — the app
 * enrols before Firebase hands one over — and one with no public key
 * cannot be sent a sealed payload at all. Either combination has to fall
 * back to the poll rather than producing a push to nowhere, and the
 * cheapest way for that to break is somebody "simplifying" the condition.
 *
 * <b>The rate limiter counts the call it is asked about.</b> Asking is
 * not free — that is the point — so a caller that checked twice before
 * acting would burn two of its own allowance.
 */

covers(\Fellowship\Devices\Device::class, \Fellowship\Core\RateLimiter::class, \Fellowship\Admin\MessagesPage::class, \Fellowship\Admin\ComposePage::class, \Fellowship\Admin\DevicesPage::class, \Fellowship\Admin\SettingsPage::class);

beforeEach(function () {
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    // add_menu_page and add_submenu_page are deliberately not stubbed
    // here. Brain Monkey allows one definition per function, so a
    // when() in setUp would silently prevent the expect() the two menu
    // tests below rely on -- the expectation is created, never
    // matched, and fails with "called 0 times" while the code plainly
    // called it.
});

// ── A device's own answers ────────────────────────────────────────

test('a handset with everything it needs is pushed', function () {
    expect(coreUnitsDevice()->wantsPush())->toBeTrue();
});

test('a handset with no token yet is not pushed', function () {
    // Normal at enrolment: the app signs in before Firebase has
    // handed a token over. It polls until the next launch.
    expect(coreUnitsDevice(pushToken: '')->wantsPush())->toBeFalse();
});

test('a handset with no public key is not pushed', function () {
    // There would be nothing to seal the payload to, and an unsealed
    // push is the one thing this design refuses.
    expect(coreUnitsDevice(publicKey: '')->wantsPush())->toBeFalse();
});

test('a handset on no push transport is not pushed', function () {
    expect(coreUnitsDevice(pushProvider: '')->wantsPush())->toBeFalse();
});

test('a pushable handset has no blocker to report', function () {
    expect(coreUnitsDevice()->pushBlocker())->toBe('');
});

test('the blocker names the missing token', function () {
    // The one that resolves itself. Saying so stops somebody going to
    // the Firebase console over a handset that is merely new.
    expect(coreUnitsDevice(pushToken: '')->pushBlocker())->toBe('no push token yet');
});

test('the blocker names the missing key', function () {
    expect(coreUnitsDevice(publicKey: '')->pushBlocker())->toBe('no public key');
});

test('the blocker names an absent transport', function () {
    expect(coreUnitsDevice(pushProvider: '')->pushBlocker())->toBe('enrolled with no push transport');
});

test('the blocker quotes an unrecognised transport', function () {
    // Not the same fault as none at all: a value here means the
    // handset claimed something this build does not deliver through,
    // which is a wiring mistake rather than a handset waiting on
    // Firebase.
    expect(coreUnitsDevice(pushProvider: 'apns')->pushBlocker())->toBe('push transport is "apns", not FCM');
});

test('every blocker agrees with wants push', function () {
    // The two must never disagree: a device that is pushed while
    // reporting a reason it cannot be, or refused while reporting
    // none, would make the admin table and the log lie in opposite
    // directions.
    $devices = [
        coreUnitsDevice(),
        coreUnitsDevice(pushToken: ''),
        coreUnitsDevice(publicKey: ''),
        coreUnitsDevice(pushProvider: ''),
        coreUnitsDevice(pushProvider: 'apns'),
    ];

    foreach ($devices as $device) {
        expect($device->pushBlocker() === '')->toBe($device->wantsPush());
    }
});

test('a revoked handset says so', function () {
    expect(coreUnitsDevice(revokedAt: 1788000500)->isRevoked())->toBeTrue();
    expect(coreUnitsDevice()->isRevoked())->toBeFalse();
});

test('a key fault is remembered', function () {
    expect(coreUnitsDevice(keyFaultAt: 1788000900)->hasKeyFault())->toBeTrue();
    expect(coreUnitsDevice()->hasKeyFault())->toBeFalse();
});

test('only the two known platforms are accepted', function () {
    // The platform decides the delivery path, so guessing would mean
    // silently enrolling a handset that never receives anything.
    expect(Device::normalisePlatform('  Android '))->toBe('android');
    expect(Device::normalisePlatform('iOS'))->toBe('ios');
    expect(Device::normalisePlatform('blackberry'))->toBe('');
    expect(Device::normalisePlatform(''))->toBe('');
});

// ── The rate limiter ──────────────────────────────────────────────

test('the first calls are allowed and the next is not', function () {
    $limiter = new RateLimiter();

    expect($limiter->overLimit('send_4', 3, 60))->toBeFalse();
    expect($limiter->overLimit('send_4', 3, 60))->toBeFalse();
    expect($limiter->overLimit('send_4', 3, 60))->toBeFalse();
    expect($limiter->overLimit('send_4', 3, 60))->toBeTrue();
});

test('two callers do not share an allowance', function () {
    // Keyed per device, so one handset sending hard cannot lock
    // another out.
    $limiter = new RateLimiter();

    $limiter->overLimit('send_4', 1, 60);

    expect($limiter->overLimit('send_4', 1, 60))->toBeTrue();
    expect($limiter->overLimit('send_9', 1, 60))->toBeFalse();
});

test('a zero length window is treated as one second', function () {
    // Otherwise the bucket key divides by zero.
    $limiter = new RateLimiter();

    expect($limiter->overLimit('send_4', 2, 0))->toBeFalse();
});

test('an address that is not an address is unknown', function () {
    // The value is used as a rate-limit key, so a spoofed header must
    // not become an unbounded set of buckets.
    $_SERVER['REMOTE_ADDR'] = 'not-an-ip';

    expect((new RateLimiter())->clientIp())->toBe('unknown');

    $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

    expect((new RateLimiter())->clientIp())->toBe('203.0.113.4');
});

// ── The menus themselves ──────────────────────────────────────────
//
// Brain Monkey's expect() is called as Functions\expect() rather than
// imported: a `use function Brain\Monkey\Functions\expect` shadows Pest's
// expect() for the whole file.

test('the top level menu is added with its own first item', function () {
    // Otherwise WordPress derives a duplicate first entry from the
    // menu title.
    Functions\expect('add_menu_page')->once()->andReturn('toplevel_page_fellowship');
    Functions\expect('add_submenu_page')->once()->andReturn('fellowship_page_x');

    coreUnitsMessagesPage()->addMenu();
});

test('the other screens attach to that menu', function () {
    Functions\expect('add_submenu_page')->times(3)->andReturn('fellowship_page_x');

    coreUnitsComposePage()->addMenu();
    coreUnitsDevicesPage()->addMenu();
    (new SettingsPage(new Settings()))->addMenu();
});

// ── Fixtures ──────────────────────────────────────────────────────

function coreUnitsDevice(
    string $pushProvider = 'fcm',
    string $pushToken = 'token-1',
    string $publicKey = 'spki',
    ?int $revokedAt = null,
    ?int $keyFaultAt = null,
): Device {
    return new Device(
        4,
        'member@example.org',
        7,
        'Pixel 6a',
        'android',
        $publicKey,
        $pushProvider,
        $pushToken,
        1788000000,
        0,
        $revokedAt,
        $keyFaultAt,
    );
}

function coreUnitsMessagesPage(): MessagesPage
{
    return new MessagesPage(new InMemoryMessageRepository(), new InMemoryRecipientRepository());
}

function coreUnitsComposePage(): ComposePage
{
    $members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
    ]);
    $gate = new MemberGate($members);
    $settings = new Settings();

    return new ComposePage(
        new MessageApi(
            new MessageDispatcher(
                new InMemoryMessageRepository(),
                new InMemoryRecipientRepository(),
                new InMemoryDeviceRepository(),
                new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
            ),
            new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
            new SpyAuditLogger(),
        ),
        new InMemoryCommitteeRepository(),
    );
}

function coreUnitsDevicesPage(): DevicesPage
{
    $members = new InMemoryMemberRepository([]);
    $gate = new MemberGate($members);

    return new DevicesPage(
        new InMemoryDeviceRepository(),
        $members,
        new SpyAuditLogger(),
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        $gate,
    );
}
