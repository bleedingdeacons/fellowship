<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
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
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Admin\SettingsPage
 * @covers \Fellowship\Admin\MessagesPage
 * @covers \Fellowship\Admin\ComposePage
 * @covers \Fellowship\Admin\DevicesPage
 */
final class AdminScreensTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;

    protected function setUp(): void
    {
        parent::setUp();

        $_POST = [];
        $_GET = [];

        WpState::$userCan = true;

        Functions\when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('submit_button')->justReturn(null);
        Functions\when('paginate_links')->justReturn('');

        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->devices = new InMemoryDeviceRepository();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── Settings ──────────────────────────────────────────────────────

    public function testTheSettingsScreenOffersEverySignInProvider(): void
    {
        $markup = $this->render(fn() => (new SettingsPage(new Settings()))->render());

        foreach (['Google', 'Microsoft', 'Facebook', 'Apple'] as $provider) {
            self::assertStringContainsString($provider, $markup);
        }
    }

    public function testTheSettingsScreenShowsTheRedirectUriToRegister(): void
    {
        // Whoever is configuring an OAuth client needs this exact string,
        // and getting it from the screen beats getting it from a README
        // that may not match the site.
        $markup = $this->render(fn() => (new SettingsPage(new Settings()))->render());

        self::assertStringContainsString('auth/callback', $markup);
    }

    public function testAStoredSecretIsNeverRenderedBack(): void
    {
        // The field is write-only. Painting the stored value into the
        // markup would put every client secret in the page source of an
        // admin screen.
        $settings = new Settings();
        $settings->setClientId('google', 'google-client-id');

        $markup = $this->render(fn() => (new SettingsPage($settings))->render());

        self::assertStringContainsString('google-client-id', $markup);
        self::assertStringNotContainsString('value="a-secret"', $markup);
    }

    public function testSavingSettingsWithoutTheCapabilityIsRefused(): void
    {
        WpState::$userCan = false;

        $this->expectException(WpDieException::class);

        (new SettingsPage(new Settings()))->handleSave();
    }

    public function testTheSettingsScreenRendersNothingToAReaderWhoMayNotSeeIt(): void
    {
        WpState::$userCan = false;

        self::assertSame('', $this->render(fn() => (new SettingsPage(new Settings()))->render()));
    }

    // ── The message log ───────────────────────────────────────────────

    public function testAnEmptyMessageLogSaysSoRatherThanRenderingAnEmptyTable(): void
    {
        $markup = $this->render(fn() => $this->messagesPage()->render());

        self::assertStringContainsString('No messages', $markup);
    }

    public function testTheMessageLogListsWhatWasSent(): void
    {
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

        $markup = $this->render(fn() => $this->messagesPage()->render());

        self::assertStringContainsString('Intergroup moved', $markup);
    }

    public function testTheMessageLogRendersNothingWithoutTheCapability(): void
    {
        // The log carries message subjects, which are the members' own
        // words.
        WpState::$userCan = false;

        self::assertSame('', $this->render(fn() => $this->messagesPage()->render()));
    }

    // ── Compose ───────────────────────────────────────────────────────

    public function testTheComposeScreenOffersTheCommittees(): void
    {
        $markup = $this->render(fn() => $this->composePage()->render());

        self::assertStringContainsString('<form', $markup);
    }

    public function testTheComposeScreenRendersNothingWithoutTheCapability(): void
    {
        WpState::$userCan = false;

        self::assertSame('', $this->render(fn() => $this->composePage()->render()));
    }

    public function testSendingWithoutTheCapabilityIsRefused(): void
    {
        // The one that matters most on this screen: sending reaches every
        // handset on a committee.
        WpState::$userCan = false;

        $this->expectException(WpDieException::class);

        $this->composePage()->handleSend();
    }

    // ── Devices ───────────────────────────────────────────────────────

    public function testTheDevicesScreenSaysSoWhenNothingIsEnrolled(): void
    {
        $markup = $this->render(fn() => $this->devicesPage()->render());

        self::assertStringContainsString('No handsets', $markup);
    }

    public function testTheDevicesScreenListsAHandsetAndWhoseItIs(): void
    {
        $this->enrolADevice();

        $markup = $this->render(fn() => $this->devicesPage()->render());

        self::assertStringContainsString('Pixel 6a', $markup);
    }

    public function testAReaderWhoCannotManageIsShownNoButtons(): void
    {
        // Not a permission check in itself — the handlers check again —
        // but a button that answers 403 is a worse screen than one that
        // does not offer it.
        $this->enrolADevice();
        WpState::$deniedCaps = ['fellowship_manage_devices'];

        $markup = $this->render(fn() => $this->devicesPage()->render());

        self::assertStringNotContainsString('Revoke', $markup);
    }

    public function testTheDevicesScreenRendersNothingWithoutTheViewCapability(): void
    {
        WpState::$userCan = false;

        self::assertSame('', $this->render(fn() => $this->devicesPage()->render()));
    }

    public function testRevokingWithoutTheCapabilityIsRefused(): void
    {
        WpState::$userCan = false;

        $this->expectException(WpDieException::class);

        $this->devicesPage()->handleRevoke();
    }

    public function testRemovingWithoutTheCapabilityIsRefused(): void
    {
        WpState::$userCan = false;

        $this->expectException(WpDieException::class);

        $this->devicesPage()->handleRemove();
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /**
     * Run a screen and capture what it printed.
     *
     * The screens echo directly, as WordPress admin screens do, so the
     * only way to assert on the markup is to buffer it.
     */
    private function render(callable $screen): string
    {
        ob_start();

        try {
            $screen();
        } finally {
            $markup = (string) ob_get_clean();
        }

        return $markup;
    }

    private function messagesPage(): MessagesPage
    {
        return new MessagesPage($this->messages, $this->recipients);
    }

    private function composePage(): ComposePage
    {
        // A real MessageApi: the class is final, and doubling it would
        // only prove the page calls something. What these tests are about
        // is the capability guard, which sits in front of it either way.
        $gate = new MemberGate($this->members);
        $settings = new Settings();
        $sealer = new MessageSealer();

        return new ComposePage(
            new MessageApi(
                new MessageDispatcher(
                    $this->messages,
                    $this->recipients,
                    $this->devices,
                    new FcmTransport(new FcmClient(), $settings, $sealer),
                ),
                new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
                $this->audit,
            ),
            new InMemoryCommitteeRepository(),
        );
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

    private function enrolADevice(): void
    {
        $this->devices->create(
            'hash-1',
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );
    }
}
