<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use function Brain\Monkey\Actions\expectAdded;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
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
 * What each screen says after an action, and how the menu is put
 * together.
 *
 * <b>The notice is the only feedback these screens give.</b> Every POST
 * handler ends in a redirect carrying a one-word result, so if a result
 * code does not resolve to a message the member of the intergroup running
 * the action sees a page that looks exactly as it did before — which
 * reads as "nothing happened" whether it worked or not. Each code is
 * therefore asserted to produce visible text.
 *
 * <b>The menu order is load-bearing.</b> MessagesPage registers the
 * top-level Fellowship menu and the other three attach to its slug. They
 * all use the same admin_menu hook, so callbacks fire in registration
 * order and a submenu registered before its parent exists falls back to a
 * URL that goes nowhere.
 */

covers(\Fellowship\Admin\ComposePage::class, \Fellowship\Admin\DevicesPage::class, \Fellowship\Admin\SettingsPage::class, \Fellowship\Admin\MessagesPage::class, \Fellowship\Messaging\MessageApi::class);

beforeEach(function () {
    $_GET = [];
    $_POST = [];
    WpState::$userCan = true;

    when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
    when('get_current_user_id')->justReturn(3);
    when('submit_button')->justReturn(null);
    when('paginate_links')->justReturn('');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
    when('add_menu_page')->justReturn('toplevel_page_fellowship');
    when('add_submenu_page')->justReturn('fellowship_page_x');
    when('wp_generate_uuid4')->alias(static fn(): string => '11111111-2222-4333-8444-555555555555');

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->devices = new InMemoryDeviceRepository();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
    ]);
});

// ── Notices ───────────────────────────────────────────────────────

test('each device result says something', function () {
    foreach (['revoked', 'removed', 'code_sent'] as $result) {
        $_GET['fellowship_result'] = $result;

        expect(noticeFrom(fn() => adminNoticesDevicesPage()->render()))->not->toBe('', $result . ' produced no visible notice.');
    }
});

test('each device refusal says something different', function () {
    // Three ways the password code does not go out, each needing a
    // different thing from whoever reads it.
    $seen = [];

    foreach (['code_bad_address', 'code_not_a_member', 'code_too_soon'] as $result) {
        $_GET['fellowship_result'] = $result;

        $seen[] = noticeFrom(fn() => adminNoticesDevicesPage()->render());
    }

    expect(array_unique($seen))->toHaveCount(3, 'Two refusals read the same.');
});

test('the compose screen reports a send', function () {
    $_GET['fellowship_result'] = 'sent';

    expect(noticeFrom(fn() => adminNoticesComposePage()->render()))->toContain('sent');
});

test('the compose screen shows the stored reason', function () {
    // The reason waits in a one-shot transient rather than the query
    // string. If it were not read back the member would see a bare
    // "error" and no way to act on it.
    $_GET['fellowship_result'] = 'error';
    set_transient('fellowship_compose_error_3', 'Choose who this message is for.', 60);

    $markup = noticeFrom(fn() => adminNoticesComposePage()->render());

    expect($markup)->toContain('Choose who');
});

test('the settings screen reports a save', function () {
    $_GET['fellowship_result'] = 'saved';

    expect(noticeFrom(fn() => (new SettingsPage(new Settings()))->render()))->not->toBe('');
});

test('the settings screen reports a service account it would not take', function () {
    $_GET['fellowship_result'] = 'bad_service_account';

    expect(noticeFrom(fn() => (new SettingsPage(new Settings()))->render()))->not->toBe('');
});

test('a result nobody issued says nothing', function () {
    // A hand-edited URL should not be able to put arbitrary chrome on
    // the screen.
    $_GET['fellowship_result'] = 'made-up';

    expect(noticeFrom(fn() => adminNoticesDevicesPage()->render()))->toBe('');
});

// ── The menu ──────────────────────────────────────────────────────

test('the messages screen owns the top level menu', function () {
    // The others attach to its slug, and all four use the same hook,
    // so a submenu registered before its parent exists falls back to
    // a URL that goes nowhere.
    expectAdded('admin_menu')->once();

    (new MessagesPage($this->messages, $this->recipients))->register();
});

test('every screen registers its menu', function () {
    expectAdded('admin_menu')->times(4);

    (new MessagesPage($this->messages, $this->recipients))->register();
    adminNoticesComposePage()->register();
    adminNoticesDevicesPage()->register();
    (new SettingsPage(new Settings()))->register();
});

test('the screens with actions register their handlers', function () {
    // Compose registers one admin_post action; devices registers
    // three. A handler that is never hooked is a button that posts
    // to a URL WordPress answers with -1.
    expectAdded('admin_post_' . ComposePage::SEND_ACTION)->once();

    adminNoticesComposePage()->register();
});

test('the device screen registers all three of its actions', function () {
    foreach ([DevicesPage::REVOKE_ACTION, DevicesPage::REMOVE_ACTION, DevicesPage::RESET_ACTION] as $action) {
        expectAdded('admin_post_' . $action)->once();
    }

    adminNoticesDevicesPage()->register();
});

// ── The action form of the send API ───────────────────────────────

test('the send API is reachable as an action', function () {
    // Another plugin sends by firing a hook rather than by resolving
    // anything out of Unity's container.
    expectAdded('fellowship/send_message')->once();

    adminNoticesApi()->register();
});

// ── Fixtures ──────────────────────────────────────────────────────

/** Render a screen and return only its notice markup. */
function noticeFrom(callable $screen): string
{
    $markup = captureOutput($screen);

    if (preg_match('~<div class="notice[^"]*">(.*?)</div>~s', $markup, $matches) !== 1) {
        return '';
    }

    return trim(strip_tags($matches[1]));
}

function adminNoticesDevicesPage(): DevicesPage
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

function adminNoticesComposePage(): ComposePage
{
    return new ComposePage(adminNoticesApi(), new InMemoryCommitteeRepository());
}

function adminNoticesApi(): MessageApi
{
    $gate = new MemberGate(test()->members);
    $settings = new Settings();

    return new MessageApi(
        new MessageDispatcher(
            test()->messages,
            test()->recipients,
            test()->devices,
            new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
        ),
        new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
        test()->audit,
    );
}
