<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * The states an admin screen only reaches when something is wrong.
 *
 * <b>Every branch here is one somebody meets on a bad day</b>, which is
 * exactly when a screen has to be right: a handset that cannot read what
 * it is sent, a member deleted out from under a device row, a service
 * account that was pasted in but will not parse. The happy path is
 * covered elsewhere; what is asserted here is that none of these renders
 * as a blank cell, and that each says something different from the
 * others — a screen that reports two distinct faults identically is a
 * screen that sends somebody looking in the wrong place.
 *
 * <b>The fan-out records "pushed" per member, not per device.</b> A
 * member with two handsets gets one recipient row, so "at least one of
 * their handsets was told" is the honest claim — see Recipient::$pushedAt
 * on why it is not called delivery.
 *
 * @covers \Fellowship\Admin\SettingsPage
 * @covers \Fellowship\Admin\DevicesPage
 * @covers \Fellowship\Admin\ComposePage
 * @covers \Fellowship\Messaging\MessageDispatcher
 */
final class AdminBranchesTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;

    protected function setUp(): void
    {
        parent::setUp();

        $_POST = [];
        $_GET = [];
        WpState::$userCan = true;
        FakeWpHttp::reset();

        Functions\when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('submit_button')->justReturn(null);
        Functions\when('paginate_links')->justReturn('');
        Functions\when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
        Functions\when('wp_generate_uuid4')->alias(static fn(): string => '1111-' . random_int(1, 999999999));

        $this->devices = new InMemoryDeviceRepository();
        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── The settings screen ───────────────────────────────────────────

    public function testAStoredServiceAccountIsNamedByItsProject(): void
    {
        // Which is how somebody checks they pasted the right one in,
        // without the screen ever showing the credential back.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $markup = $this->render(fn() => (new SettingsPage($settings))->render());

        self::assertStringContainsString('intergroup-fellowship', $markup);
    }

    public function testAServiceAccountThatWillNotParseIsSaidToBeBroken(): void
    {
        // A row that is present but unreadable pushes nothing, and looks
        // identical to a working one from the options table.
        $settings = new Settings();
        $settings->setFcmServiceAccount('{"project_id":"x"}');

        $markup = $this->render(fn() => (new SettingsPage($settings))->render());

        self::assertStringContainsString('could not be read', $markup);
    }

    public function testTheScreenSaysWhenASecretIsStoredWithoutShowingIt(): void
    {
        $settings = new Settings();
        $settings->setClientSecret('google', 'a-client-secret');

        $markup = $this->render(fn() => (new SettingsPage($settings))->render());

        self::assertStringContainsString('A secret is stored', $markup);
        self::assertStringNotContainsString('a-client-secret', $markup);
    }

    public function testAServiceAccountCanBeClearedOutright(): void
    {
        // Not the same as leaving the field blank, which keeps what is
        // stored. There has to be a way to take one off a site.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $_POST['clear_fcm'] = '1';

        self::assertSame('saved', (new SettingsPage($settings))->saveFromRequest());
        self::assertSame('', $settings->getFcmServiceAccount());
    }

    public function testAServiceAccountThatWillNotParseIsRefusedRatherThanStored(): void
    {
        // The moment to find out is now, not at the first message.
        $settings = new Settings();

        $_POST['fcm_service_account'] = '{"project_id":"x"}';

        self::assertSame('bad_service_account', (new SettingsPage($settings))->saveFromRequest());
        self::assertSame('', $settings->getFcmServiceAccount());
    }

    // ── The device list ───────────────────────────────────────────────

    public function testARevokedHandsetIsShownAsRevokedRatherThanHidden(): void
    {
        // The row stays so somebody can see what happened and when.
        $this->enrol();
        $this->devices->revoke(1, 1788000100);

        self::assertStringContainsString('Revoked', $this->render(fn() => $this->devicesPage()->render()));
    }

    public function testAHandsetThatCannotReadItsMessagesIsFlaggedLoudly(): void
    {
        // Enrolled, looks healthy, and cannot read a word it is sent.
        // The only place that is visible is this screen.
        $this->enrol();
        $this->devices->markKeyFault(1, 1788000100);

        self::assertStringContainsString('Cannot read messages', $this->render(fn() => $this->devicesPage()->render()));
    }

    public function testADeviceWhoseMemberHasGoneSaysSoRatherThanShowingABlank(): void
    {
        // It means a handset that will fail its next request, and
        // somebody may want to remove the row.
        $this->enrol();
        $this->members = new InMemoryMemberRepository([]);

        self::assertStringContainsString('no member record', $this->render(fn() => $this->devicesPage()->render()));
    }

    public function testAMemberWithNoAnonymousNameIsNamedAsSuch(): void
    {
        $this->enrol();
        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: '', personalEmail: self::MEMBER),
        ]);

        self::assertStringContainsString('unnamed member', $this->render(fn() => $this->devicesPage()->render()));
    }

    public function testAMemberIsFoundByAddressWhenTheDeviceCarriesNoId(): void
    {
        // Device rows predating the id column carry only the address,
        // and they still belong to somebody.
        $this->devices->create('hash-1', self::MEMBER, 0, 'Pixel 6a', 'android', 'spki', 'fcm', 'token-1', 1788000000);

        self::assertStringContainsString('Dave P', $this->render(fn() => $this->devicesPage()->render()));
    }

    // ── The compose screen ────────────────────────────────────────────

    public function testEveryCommitteeIsOfferedAsAnAudience(): void
    {
        $markup = $this->render(fn() => $this->composePage([
            new CommitteeStub(id: 2, slug: 'steering', name: 'Steering'),
            new CommitteeStub(id: 3, slug: 'archives', name: 'Archives'),
        ])->render());

        self::assertStringContainsString('steering', $markup);
        self::assertStringContainsString('Archives', $markup);
    }

    public function testAFailureWithNoStoredReasonStillSaysSomething(): void
    {
        // The transient is read once and deleted, so a refresh finds
        // nothing — and a bare "error" with no words is worse than a
        // generic sentence.
        $_GET['fellowship_result'] = 'error';

        self::assertStringContainsString('could not be sent', $this->render(fn() => $this->composePage()->render()));
    }

    // ── The fan-out ───────────────────────────────────────────────────

    public function testAMemberWithAHandsetIsMarkedAsPushedTo(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $this->enrol($this->publicKey());

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{}');

        $message = $this->dispatch($settings);

        $recipients = $this->recipients->forMessage($message);

        self::assertCount(1, $recipients);
        self::assertNotNull($recipients[0]->pushedAt);
    }

    public function testAMemberWithNoHandsetIsStillARecipient(): void
    {
        // They will read it when they enrol. A recipient row that is
        // never written is a message they can never see.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $message = $this->dispatch($settings);

        $recipients = $this->recipients->forMessage($message);

        self::assertCount(1, $recipients);
        self::assertNull($recipients[0]->pushedAt);
    }

    public function testAPushThatFailsLeavesTheRecipientUnpushed(): void
    {
        // Not an error: the handset collects it on its next poll, and
        // claiming it was pushed would make the log say something untrue.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $this->enrol($this->publicKey());

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(404, '{"error":{"status":"NOT_FOUND"}}');

        $message = $this->dispatch($settings);

        self::assertNull($this->recipients->forMessage($message)[0]->pushedAt);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function dispatch(Settings $settings): int
    {
        $request = MessageRequest::fromArray([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => [self::MEMBER],
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);

        $dispatcher = new MessageDispatcher(
            $this->messages,
            $this->recipients,
            $this->devices,
            new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
        );

        return $dispatcher->dispatch(
            $request,
            [['email' => self::MEMBER, 'member_id' => 7]],
            '',
            0,
            'Intergroup',
        )->id;
    }

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

    /** @param list<CommitteeStub> $committees */
    private function composePage(array $committees = []): ComposePage
    {
        $gate = new MemberGate($this->members);
        $settings = new Settings();

        return new ComposePage(
            new MessageApi(
                new MessageDispatcher(
                    $this->messages,
                    $this->recipients,
                    $this->devices,
                    new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
                ),
                new RecipientResolver($this->members, new InMemoryCommitteeRepository($committees), $gate),
                $this->audit,
            ),
            new InMemoryCommitteeRepository($committees),
        );
    }

    private function enrol(string $publicKey = 'spki'): void
    {
        $this->devices->create(
            'hash-1',
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            $publicKey,
            'fcm',
            'token-1',
            1788000000,
        );
    }

    private function accountJson(): string
    {
        // Signed with a keypair generated for this run. A fake key would
        // make every push stop before the first HTTP call, so the fan-out
        // below would assert nothing at all.
        return (string) wp_json_encode([
            'type' => 'service_account',
            'project_id' => 'intergroup-fellowship',
            'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
            'private_key' => self::privateKey(),
            'token_uri' => 'https://oauth2.googleapis.com/token',
        ]);
    }

    private static function privateKey(): string
    {
        static $pem = null;

        if ($pem === null) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            if ($resource === false) {
                self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
            }

            openssl_pkey_export($resource, $exported);
            $pem = (string) $exported;
        }

        return $pem;
    }

    private function publicKey(): string
    {
        $resource = openssl_pkey_get_private(self::privateKey());
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }
}
