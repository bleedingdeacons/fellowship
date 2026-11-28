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
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Tests\Support\InMemoryLinkDevices;
use Fellowship\Tests\Support\InMemoryMessageLog;
use Fellowship\Tests\Support\RecordingDelivery;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * The small classes everything else leans on.
 *
 * <b>The rate limiter counts the call it is asked about.</b> Asking is
 * not free — that is the point — so a caller that checked twice before
 * acting would burn two of its own allowance.
 */

covers(\Fellowship\Core\RateLimiter::class, \Fellowship\Admin\MessagesPage::class, \Fellowship\Admin\ComposePage::class, \Fellowship\Admin\DevicesPage::class, \Fellowship\Admin\SettingsPage::class);

beforeEach(function () {
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    // add_menu_page and add_submenu_page are deliberately not stubbed
    // here. Brain Monkey allows one definition per function, so a
    // when() in setUp would silently prevent the expect() the two menu
    // tests below rely on -- the expectation is created, never
    // matched, and fails with "called 0 times" while the code plainly
    // called it.
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

function coreUnitsMessagesPage(): MessagesPage
{
    return new MessagesPage(new InMemoryMessageLog(), new InMemoryMemberRepository([]));
}

function coreUnitsComposePage(): ComposePage
{
    $members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
    ]);
    $gate = new MemberGate($members);

    return new ComposePage(
        new MessageApi(
            new RecordingDelivery(),
            new MessageSealer(),
            new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
            new SpyAuditLogger(),
        ),
        new InMemoryCommitteeRepository(),
        $gate,
        new DirectoryPresenter($members, new InMemoryCommitteeRepository(), $gate),
    );
}

function coreUnitsDevicesPage(): DevicesPage
{
    $members = new InMemoryMemberRepository([]);
    $gate = new MemberGate($members);

    return new DevicesPage(
        new InMemoryLinkDevices(),
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
