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
use Unity\Testing\Doubles\GroupStub;
use Unity\Testing\Doubles\InMemoryGroupRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\InMemoryPositionRepository;
use Unity\Testing\Doubles\MemberStub;
use Unity\Testing\Doubles\PositionStub;
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

    // ── Home group and GSR ────────────────────────────────────────────

    public function testAMemberCarriesTheirHomeGroupAndGsrStanding(): void
    {
        // A first name does not identify anybody in an intergroup with
        // several Daves, which is why the group travels beside it — the
        // same reason Hand shows one on its own member list.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                homeGroup: 3,
                isGSR: true,
                personalEmail: self::MEMBER,
            ),
        ]);

        $groups = new InMemoryGroupRepository([new GroupStub(id: 3, title: 'Tuesday Bristol')]);

        $member = $this->presenter($groups)->forApp(false)['members'][0];

        self::assertSame('Tuesday Bristol', $member['group']);
        self::assertTrue($member['gsr']);
    }

    public function testStillNoAddressesTravelWithTheNewFields(): void
    {
        // The point of the whole class, and the fields added beside the
        // name must not quietly become a way round it.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                homeGroup: 3,
                isGSR: true,
                personalEmail: self::MEMBER,
                mobileNumber: '07700 900123',
            ),
        ]);

        $encoded = (string) json_encode(
            $this->presenter(new InMemoryGroupRepository([new GroupStub(id: 3, title: 'Tuesday Bristol')]))
                ->forApp(false),
        );

        self::assertStringNotContainsString(self::MEMBER, $encoded);
        self::assertStringNotContainsString('07700', $encoded);
    }

    public function testAMemberWithNoHomeGroupGetsAnEmptyOne(): void
    {
        // Ordinary rather than exceptional: a member need not have a
        // group recorded, and a group can be deleted while members still
        // point at it. The app leaves the line out.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                homeGroup: 99,
                personalEmail: self::MEMBER,
            ),
        ]);

        $member = $this->presenter(new InMemoryGroupRepository([]))->forApp(false)['members'][0];

        self::assertSame('', $member['group']);
        self::assertFalse($member['gsr']);
    }

    public function testTheDirectoryStillBuildsWithNoGroupRepositoryAtAll(): void
    {
        // Unity ships headless and need not have groups bound. Absent,
        // the list is built without home groups rather than not at all.
        $member = $this->presenter()->forApp(false)['members'][0];

        self::assertSame('', $member['group']);
        self::assertArrayHasKey('name', $member);
    }

    // ── Intergroup service position ───────────────────────────────────

    public function testAMemberCarriesTheirIntergroupServicePosition(): void
    {
        // Somebody writing to the Secretary is looking for a job rather
        // than a name, and has no way to tell which of these people holds
        // it from a first name and a home group.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                intergroupPosition: 855,
                personalEmail: self::MEMBER,
            ),
        ]);

        $positions = new InMemoryPositionRepository([
            new PositionStub(id: 855, longName: 'Intergroup Secretary'),
        ]);

        $member = $this->presenter(positions: $positions)->forApp(false)['members'][0];

        self::assertSame('Intergroup Secretary', $member['position']);
    }

    public function testAMemberHoldingNoPositionGetsAnEmptyOne(): void
    {
        // The ordinary case by a distance: most of the fellowship holds
        // no intergroup position at all.
        $member = $this->presenter(positions: new InMemoryPositionRepository([]))
            ->forApp(false)['members'][0];

        self::assertSame('', $member['position']);
    }

    public function testAPositionThatCannotBeNamedIsLeftEmptyRatherThanGuessed(): void
    {
        // A position can be deleted while members still point at it.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                intergroupPosition: 404,
                personalEmail: self::MEMBER,
            ),
        ]);

        $member = $this->presenter(positions: new InMemoryPositionRepository([]))
            ->forApp(false)['members'][0];

        self::assertSame('', $member['position']);
    }

    public function testTheDirectoryStillBuildsWithNoPositionRepositoryAtAll(): void
    {
        // Feature-detected exactly as groups are, and for the same
        // reason: a headless Unity need not have positions bound.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                intergroupPosition: 855,
                personalEmail: self::MEMBER,
            ),
        ]);

        $member = $this->presenter()->forApp(false)['members'][0];

        self::assertSame('', $member['position']);
        self::assertArrayHasKey('name', $member);
    }

    public function testNoAddressTravelsWithThePositionEither(): void
    {
        // A Position carries an email of its own — the role's, not the
        // member's, but an address all the same, and this class hands out
        // none of either sort.
        $this->members = new InMemoryMemberRepository([
            new MemberStub(
                id: 7,
                anonymousName: 'Dave P',
                showMemberProfile: true,
                intergroupPosition: 855,
                personalEmail: self::MEMBER,
            ),
        ]);

        $positions = new InMemoryPositionRepository([
            new PositionStub(id: 855, longName: 'Intergroup Secretary', email: 'secretary@example.org'),
        ]);

        $encoded = (string) json_encode($this->presenter(positions: $positions)->forApp(false));

        self::assertStringNotContainsString('secretary@example.org', $encoded);
        self::assertStringNotContainsString(self::MEMBER, $encoded);
    }

    private function presenter(
        ?InMemoryGroupRepository $groups = null,
        ?InMemoryPositionRepository $positions = null,
    ): DirectoryPresenter {
        return new DirectoryPresenter(
            $this->members,
            new InMemoryCommitteeRepository(),
            new MemberGate($this->members),
            $groups,
            $positions,
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
