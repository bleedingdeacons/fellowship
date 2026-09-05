<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
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
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Devices\Device
 * @covers \Fellowship\Core\RateLimiter
 * @covers \Fellowship\Admin\MessagesPage
 * @covers \Fellowship\Admin\ComposePage
 * @covers \Fellowship\Admin\DevicesPage
 * @covers \Fellowship\Admin\SettingsPage
 */
final class CoreUnitsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        // add_menu_page and add_submenu_page are deliberately not stubbed
        // here. Brain Monkey allows one definition per function, so a
        // when() in setUp would silently prevent the expect() the two menu
        // tests below rely on -- the expectation is created, never
        // matched, and fails with "called 0 times" while the code plainly
        // called it.
    }

    // ── A device's own answers ────────────────────────────────────────

    public function testAHandsetWithEverythingItNeedsIsPushed(): void
    {
        self::assertTrue($this->device()->wantsPush());
    }

    public function testAHandsetWithNoTokenYetIsNotPushed(): void
    {
        // Normal at enrolment: the app signs in before Firebase has
        // handed a token over. It polls until the next launch.
        self::assertFalse($this->device(pushToken: '')->wantsPush());
    }

    public function testAHandsetWithNoPublicKeyIsNotPushed(): void
    {
        // There would be nothing to seal the payload to, and an unsealed
        // push is the one thing this design refuses.
        self::assertFalse($this->device(publicKey: '')->wantsPush());
    }

    public function testAHandsetOnNoPushTransportIsNotPushed(): void
    {
        self::assertFalse($this->device(pushProvider: '')->wantsPush());
    }

    public function testARevokedHandsetSaysSo(): void
    {
        self::assertTrue($this->device(revokedAt: 1788000500)->isRevoked());
        self::assertFalse($this->device()->isRevoked());
    }

    public function testAKeyFaultIsRemembered(): void
    {
        self::assertTrue($this->device(keyFaultAt: 1788000900)->hasKeyFault());
        self::assertFalse($this->device()->hasKeyFault());
    }

    public function testOnlyTheTwoKnownPlatformsAreAccepted(): void
    {
        // The platform decides the delivery path, so guessing would mean
        // silently enrolling a handset that never receives anything.
        self::assertSame('android', Device::normalisePlatform('  Android '));
        self::assertSame('ios', Device::normalisePlatform('iOS'));
        self::assertSame('', Device::normalisePlatform('blackberry'));
        self::assertSame('', Device::normalisePlatform(''));
    }

    // ── The rate limiter ──────────────────────────────────────────────

    public function testTheFirstCallsAreAllowedAndTheNextIsNot(): void
    {
        $limiter = new RateLimiter();

        self::assertFalse($limiter->overLimit('send_4', 3, 60));
        self::assertFalse($limiter->overLimit('send_4', 3, 60));
        self::assertFalse($limiter->overLimit('send_4', 3, 60));
        self::assertTrue($limiter->overLimit('send_4', 3, 60));
    }

    public function testTwoCallersDoNotShareAnAllowance(): void
    {
        // Keyed per device, so one handset sending hard cannot lock
        // another out.
        $limiter = new RateLimiter();

        $limiter->overLimit('send_4', 1, 60);

        self::assertTrue($limiter->overLimit('send_4', 1, 60));
        self::assertFalse($limiter->overLimit('send_9', 1, 60));
    }

    public function testAZeroLengthWindowIsTreatedAsOneSecond(): void
    {
        // Otherwise the bucket key divides by zero.
        $limiter = new RateLimiter();

        self::assertFalse($limiter->overLimit('send_4', 2, 0));
    }

    public function testAnAddressThatIsNotAnAddressIsUnknown(): void
    {
        // The value is used as a rate-limit key, so a spoofed header must
        // not become an unbounded set of buckets.
        $_SERVER['REMOTE_ADDR'] = 'not-an-ip';

        self::assertSame('unknown', (new RateLimiter())->clientIp());

        $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

        self::assertSame('203.0.113.4', (new RateLimiter())->clientIp());
    }

    // ── The menus themselves ──────────────────────────────────────────

    public function testTheTopLevelMenuIsAddedWithItsOwnFirstItem(): void
    {
        // Otherwise WordPress derives a duplicate first entry from the
        // menu title.
        Functions\expect('add_menu_page')->once()->andReturn('toplevel_page_fellowship');
        Functions\expect('add_submenu_page')->once()->andReturn('fellowship_page_x');

        $this->messagesPage()->addMenu();
    }

    public function testTheOtherScreensAttachToThatMenu(): void
    {
        Functions\expect('add_submenu_page')->times(3)->andReturn('fellowship_page_x');

        $this->composePage()->addMenu();
        $this->devicesPage()->addMenu();
        (new SettingsPage(new Settings()))->addMenu();
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function device(
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

    private function messagesPage(): MessagesPage
    {
        return new MessagesPage(new InMemoryMessageRepository(), new InMemoryRecipientRepository());
    }

    private function composePage(): ComposePage
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

    private function devicesPage(): DevicesPage
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
}
