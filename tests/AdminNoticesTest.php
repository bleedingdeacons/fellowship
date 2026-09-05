<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
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
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Admin\ComposePage
 * @covers \Fellowship\Admin\DevicesPage
 * @covers \Fellowship\Admin\SettingsPage
 * @covers \Fellowship\Admin\MessagesPage
 * @covers \Fellowship\Messaging\MessageApi
 */
final class AdminNoticesTest extends TestCase
{
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;

    protected function setUp(): void
    {
        parent::setUp();

        $_GET = [];
        $_POST = [];
        WpState::$userCan = true;

        Functions\when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('submit_button')->justReturn(null);
        Functions\when('paginate_links')->justReturn('');
        Functions\when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
        Functions\when('add_menu_page')->justReturn('toplevel_page_fellowship');
        Functions\when('add_submenu_page')->justReturn('fellowship_page_x');
        Functions\when('wp_generate_uuid4')->alias(static fn(): string => '11111111-2222-4333-8444-555555555555');

        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->devices = new InMemoryDeviceRepository();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        ]);
    }

    // ── Notices ───────────────────────────────────────────────────────

    public function testEachDeviceResultSaysSomething(): void
    {
        foreach (['revoked', 'removed', 'code_sent'] as $result) {
            $_GET['fellowship_result'] = $result;

            self::assertNotSame(
                '',
                $this->noticeFrom(fn() => $this->devicesPage()->render()),
                $result . ' produced no visible notice.',
            );
        }
    }

    public function testEachDeviceRefusalSaysSomethingDifferent(): void
    {
        // Three ways the password code does not go out, each needing a
        // different thing from whoever reads it.
        $seen = [];

        foreach (['code_bad_address', 'code_not_a_member', 'code_too_soon'] as $result) {
            $_GET['fellowship_result'] = $result;

            $seen[] = $this->noticeFrom(fn() => $this->devicesPage()->render());
        }

        self::assertCount(3, array_unique($seen), 'Two refusals read the same.');
    }

    public function testTheComposeScreenReportsASend(): void
    {
        $_GET['fellowship_result'] = 'sent';

        self::assertStringContainsString('sent', $this->noticeFrom(fn() => $this->composePage()->render()));
    }

    public function testTheComposeScreenShowsTheStoredReason(): void
    {
        // The reason waits in a one-shot transient rather than the query
        // string. If it were not read back the member would see a bare
        // "error" and no way to act on it.
        $_GET['fellowship_result'] = 'error';
        set_transient('fellowship_compose_error_3', 'Choose who this message is for.', 60);

        $markup = $this->noticeFrom(fn() => $this->composePage()->render());

        self::assertStringContainsString('Choose who', $markup);
    }

    public function testTheSettingsScreenReportsASave(): void
    {
        $_GET['fellowship_result'] = 'saved';

        self::assertNotSame('', $this->noticeFrom(fn() => (new SettingsPage(new Settings()))->render()));
    }

    public function testTheSettingsScreenReportsAServiceAccountItWouldNotTake(): void
    {
        $_GET['fellowship_result'] = 'bad_service_account';

        self::assertNotSame('', $this->noticeFrom(fn() => (new SettingsPage(new Settings()))->render()));
    }

    public function testAResultNobodyIssuedSaysNothing(): void
    {
        // A hand-edited URL should not be able to put arbitrary chrome on
        // the screen.
        $_GET['fellowship_result'] = 'made-up';

        self::assertSame('', $this->noticeFrom(fn() => $this->devicesPage()->render()));
    }

    // ── The menu ──────────────────────────────────────────────────────

    public function testTheMessagesScreenOwnsTheTopLevelMenu(): void
    {
        // The others attach to its slug, and all four use the same hook,
        // so a submenu registered before its parent exists falls back to
        // a URL that goes nowhere.
        Actions\expectAdded('admin_menu')->once();

        (new MessagesPage($this->messages, $this->recipients))->register();
    }

    public function testEveryScreenRegistersItsMenu(): void
    {
        Actions\expectAdded('admin_menu')->times(4);

        (new MessagesPage($this->messages, $this->recipients))->register();
        $this->composePage()->register();
        $this->devicesPage()->register();
        (new SettingsPage(new Settings()))->register();
    }

    public function testTheScreensWithActionsRegisterTheirHandlers(): void
    {
        // Compose registers one admin_post action; devices registers
        // three. A handler that is never hooked is a button that posts
        // to a URL WordPress answers with -1.
        Actions\expectAdded('admin_post_' . ComposePage::SEND_ACTION)->once();

        $this->composePage()->register();
    }

    public function testTheDeviceScreenRegistersAllThreeOfItsActions(): void
    {
        foreach ([DevicesPage::REVOKE_ACTION, DevicesPage::REMOVE_ACTION, DevicesPage::RESET_ACTION] as $action) {
            Actions\expectAdded('admin_post_' . $action)->once();
        }

        $this->devicesPage()->register();
    }

    // ── The action form of the send API ───────────────────────────────

    public function testTheSendApiIsReachableAsAnAction(): void
    {
        // Another plugin sends by firing a hook rather than by resolving
        // anything out of Unity's container.
        Actions\expectAdded('fellowship/send_message')->once();

        $this->api()->register();
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /** Render a screen and return only its notice markup. */
    private function noticeFrom(callable $screen): string
    {
        ob_start();

        try {
            $screen();
        } finally {
            $markup = (string) ob_get_clean();
        }

        if (preg_match('~<div class="notice[^"]*">(.*?)</div>~s', $markup, $matches) !== 1) {
            return '';
        }

        return trim(strip_tags($matches[1]));
    }

    private function devicesPage(): DevicesPage
    {
        $gate = new MemberGate($this->members);

        return new DevicesPage(
            $this->devices,
            $this->members,
            $this->audit,
            new PasswordAuthenticator(
                new InMemoryPasswordCredentialRepository(),
                $gate,
                new PasswordResetMailer(),
                new PasswordPolicy(),
            ),
            $gate,
        );
    }

    private function composePage(): ComposePage
    {
        return new ComposePage($this->api(), new InMemoryCommitteeRepository());
    }

    private function api(): MessageApi
    {
        $gate = new MemberGate($this->members);
        $settings = new Settings();

        return new MessageApi(
            new MessageDispatcher(
                $this->messages,
                $this->recipients,
                $this->devices,
                new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
            ),
            new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
            $this->audit,
        );
    }
}
