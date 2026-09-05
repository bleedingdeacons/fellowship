<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Rest\DirectoryController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The address book the app is given, and the one-time codes that get a
 * handset enrolled.
 *
 * <b>The directory carries anonymous names and opaque ids, and no
 * addresses at all.</b> That is what lets a handset compose to somebody
 * without ever learning how to reach them outside Link — the app sends an
 * id back and the server resolves it. A member with no anonymous name is
 * left out entirely rather than listed as a blank row or, worse, by
 * email.
 *
 * <b>A device code is one-time and short-lived.</b> It travels back
 * through a browser redirect, where it lands in history and can be read
 * by anything else registered for the scheme, which is precisely why it
 * is worthless twice and worthless late.
 *
 * @covers \Fellowship\Directory\DirectoryPresenter
 * @covers \Fellowship\Rest\DirectoryController
 * @covers \Fellowship\Auth\DeviceCodeStore
 */
final class DirectoryTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryMemberRepository $members;
    private InMemoryDeviceRepository $devices;
    private DeviceTokenMinter $minter;
    private SpyAuditLogger $audit;
    private Settings $settings;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);

        $this->devices = new InMemoryDeviceRepository();
        $this->minter = new DeviceTokenMinter();
        $this->audit = new SpyAuditLogger();
        $this->settings = new Settings();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                personalEmail: self::MEMBER,
            ),
            new MemberStub(
                id: 8,
                anonymousName: 'Sue M',
                showMemberProfile: true,
                personalEmail: 'sue@example.org',
            ),
        ]);
    }

    // ── What the app is shown ─────────────────────────────────────────

    public function testTheDirectoryCarriesNamesAndIdsAndNoAddresses(): void
    {
        $directory = $this->presenter()->forApp(false);

        $encoded = (string) json_encode($directory);

        self::assertStringNotContainsString('@example.org', $encoded);
        self::assertStringContainsString('Dave P', $encoded);
    }

    public function testMembersAreListedByName(): void
    {
        // The app renders this straight into a picker, so the order has
        // to be one a person would expect.
        $directory = $this->presenter()->forApp(false);

        self::assertSame(['Dave P', 'Sue M'], array_column($directory['members'], 'name'));
    }

    public function testAMemberWhoIsNotListedIsLeftOut(): void
    {
        // showMemberProfile is the member's own choice about appearing in
        // a directory at all.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: false, personalEmail: self::MEMBER),
        ]);

        self::assertSame([], $this->presenter()->forApp(false)['members']);
    }

    public function testAMemberWithNoAnonymousNameIsLeftOut(): void
    {
        // There is nothing that could be shown without breaking
        // anonymity, and a blank row in a picker is worse than an absence.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: '', showMemberProfile: true, personalEmail: self::MEMBER),
        ]);

        self::assertSame([], $this->presenter()->forApp(false)['members']);
    }

    public function testCommitteesAreOnlyIncludedWhenTheSiteAllowsSendingToThem(): void
    {
        // Listing committees the app may not write to would be an empty
        // promise on a picker.
        self::assertSame([], $this->presenter()->forApp(false)['committees']);
    }

    // ── The route ─────────────────────────────────────────────────────

    public function testAnEnrolledHandsetIsGivenTheDirectory(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->index($this->request($token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertArrayHasKey('members', (array) $response->get_data());
    }

    public function testReadingTheDirectoryIsAudited(): void
    {
        // It is a list of members, so who read it and when is worth
        // recording.
        $token = $this->enrol();

        $this->controller()->index($this->request($token));

        self::assertNotEmpty($this->audit->entries);
    }

    public function testAnUnauthenticatedRequestGetsNoDirectory(): void
    {
        $response = $this->controller()->index($this->request());

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame([], $this->audit->entries);
    }

    public function testARevokedHandsetGetsNoDirectory(): void
    {
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        self::assertInstanceOf(WP_Error::class, $this->controller()->index($this->request($token)));
    }

    public function testPlainHttpGetsNoDirectory(): void
    {
        Functions\when('is_ssl')->justReturn(false);

        self::assertInstanceOf(WP_Error::class, $this->controller()->index($this->request($this->enrol())));
    }

    // ── The one-time code ─────────────────────────────────────────────

    public function testACodeCarriesTheIdentityItWasIssuedFor(): void
    {
        $store = new DeviceCodeStore();

        $code = $store->issue(new VerifiedIdentity(self::MEMBER, 'google', 'sub-1'));
        $identity = $store->consume($code);

        self::assertNotNull($identity);
        self::assertSame(self::MEMBER, $identity->email);
        self::assertSame('google', $identity->provider);
    }

    public function testACodeIsWorthlessTwice(): void
    {
        // It travels back through a browser redirect, where it lands in
        // history and can be read by anything else registered for the
        // scheme.
        $store = new DeviceCodeStore();

        $code = $store->issue(new VerifiedIdentity(self::MEMBER, 'google', 'sub-1'));

        self::assertNotNull($store->consume($code));
        self::assertNull($store->consume($code));
    }

    public function testACodeNobodyIssuedIsWorthless(): void
    {
        self::assertNull((new DeviceCodeStore())->consume('never-issued'));
        self::assertNull((new DeviceCodeStore())->consume(''));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function presenter(): DirectoryPresenter
    {
        return new DirectoryPresenter(
            $this->members,
            new InMemoryCommitteeRepository(),
            new MemberGate($this->members),
        );
    }

    private function controller(): DirectoryController
    {
        $gate = new MemberGate($this->members);

        return new DirectoryController(
            new CurrentDevice($this->devices, $this->minter, $gate, $this->members),
            $this->presenter(),
            $this->settings,
            $this->audit,
        );
    }

    private function enrol(): string
    {
        $token = $this->minter->mint();

        $this->devices->create(
            $this->minter->hash($token),
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );

        return $token;
    }

    private function request(string $token = ''): WP_REST_Request
    {
        $request = new WP_REST_Request();

        if ($token !== '') {
            $request->set_header('authorization', 'Bearer ' . $token);
        }

        return $request;
    }
}
