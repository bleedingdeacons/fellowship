<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Rest\DirectoryController;
use Fellowship\Tests\Support\MembersWithLink;
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
 */

covers(\Fellowship\Directory\DirectoryPresenter::class, \Fellowship\Rest\DirectoryController::class, \Fellowship\Auth\DeviceCodeStore::class);

const DIRECTORY_MEMBER = 'member@example.org';

/** The shape of Link's old WordPress device tokens, which nothing issues any more. */
const DIRECTORY_OLD_TOKEN = 'fdt_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

beforeEach(function () {
    when('is_ssl')->justReturn(true);

    // Who has Link on Firebase. Nobody, unless a test says otherwise.
    $this->withLink = [];
    $this->audit = new SpyAuditLogger();
    $this->settings = new Settings();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            personalEmail: DIRECTORY_MEMBER,
        ),
        new MemberStub(
            id: 8,
            anonymousName: 'Sue M',
            showMemberProfile: true,
            personalEmail: 'sue@example.org',
        ),
    ]);
});

// ── What the app is shown ─────────────────────────────────────────

test('the directory carries names and ids and no addresses', function () {
    $directory = directoryPresenter()->forApp(false);

    $encoded = (string) json_encode($directory);

    expect($encoded)->not->toContain('@example.org');
    expect($encoded)->toContain('Dave P');
});

test('members are listed by name', function () {
    // The app renders this straight into a picker, so the order has
    // to be one a person would expect.
    $directory = directoryPresenter()->forApp(false);

    expect(array_column($directory['members'], 'name'))->toBe(['Dave P', 'Sue M']);
});

test('a member with their profile hidden is still listed', function () {
    // showMemberProfile plays no part in messaging.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: false, personalEmail: DIRECTORY_MEMBER),
    ]);

    expect(array_column(directoryPresenter()->forApp(false)['members'], 'name'))->toBe(['Dave P']);
});

test('a member with no anonymous name is left out', function () {
    // There is nothing that could be shown without breaking
    // anonymity, and a blank row in a picker is worse than an absence.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: '', showMemberProfile: true, personalEmail: DIRECTORY_MEMBER),
    ]);

    expect(directoryPresenter()->forApp(false)['members'])->toBe([]);
});

test('committees are only included when the site allows sending to them', function () {
    // Listing committees the app may not write to would be an empty
    // promise on a picker.
    expect(directoryPresenter()->forApp(false)['committees'])->toBe([]);
});

test('all gsrs is only offered when the site allows committee sends', function () {
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: DIRECTORY_MEMBER, isGSR: true),
    ]);

    expect(directoryPresenter()->forApp(false)['gsrs'])->toBeNull();
    expect(directoryPresenter()->forApp(true)['gsrs'])->toBe(1);
});

test('the gsr count includes gsrs who are not listed', function () {
    // The send reaches them, so the count the sender is shown must too.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: DIRECTORY_MEMBER, isGSR: true),
        new MemberStub(id: 8, anonymousName: '', showMemberProfile: true, personalEmail: 'sue@example.org', isGSR: true),
        new MemberStub(id: 9, anonymousName: 'Jo B', showMemberProfile: true, personalEmail: 'jo@example.org'),
        new MemberStub(id: 10, anonymousName: 'No Address', showMemberProfile: true, personalEmail: '', isGSR: true),
    ]);

    $directory = directoryPresenter()->forApp(true);

    expect($directory['gsrs'])->toBe(2);
    expect(array_column($directory['members'], 'name'))->toBe(['Dave P', 'Jo B']);
});

test('all gsrs is not offered when there are none', function () {
    // A choice that would reach nobody is not a choice.
    expect(directoryPresenter()->forApp(true)['gsrs'])->toBeNull();
});

// ── The route ─────────────────────────────────────────────────────

// A Firebase device reading it, and the audit entry that leaves, are in
// FirebaseDevicesTest.

test('an old WordPress device token gets no directory', function () {
    // Link has none any more, and the only ones still issued belong to
    // another audience, such as Register's tablets.
    $response = directoryController()->index(directoryRequest(DIRECTORY_OLD_TOKEN));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_data()['status'])->toBe(401);
    expect($this->audit->entries)->toBe([]);
});

test('an unauthenticated request gets no directory', function () {
    $response = directoryController()->index(directoryRequest());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($this->audit->entries)->toBe([]);
});

test('plain HTTP gets no directory', function () {
    when('is_ssl')->justReturn(false);

    expect(directoryController()->index(directoryRequest(DIRECTORY_OLD_TOKEN)))->toBeInstanceOf(WP_Error::class);
});

// ── The one-time code ─────────────────────────────────────────────

test('a code carries the identity it was issued for', function () {
    $store = new DeviceCodeStore();

    $code = $store->issue(new VerifiedIdentity(DIRECTORY_MEMBER, 'google', 'sub-1'), 'freedom');
    $identity = $store->redeem($code, 'freedom')?->identity;

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe(DIRECTORY_MEMBER);
    expect($identity->provider)->toBe('google');
});

test('a code is worthless twice', function () {
    // It travels back through a browser redirect, where it lands in
    // history and can be read by anything else registered for the
    // scheme.
    $store = new DeviceCodeStore();

    $code = $store->issue(new VerifiedIdentity(DIRECTORY_MEMBER, 'google', 'sub-1'), 'freedom');

    expect($store->redeem($code, 'freedom'))->not->toBeNull();
    expect($store->redeem($code, 'freedom'))->toBeNull();
});

test('a code nobody issued is worthless', function () {
    expect((new DeviceCodeStore())->redeem('never-issued', 'freedom'))->toBeNull();
    expect((new DeviceCodeStore())->redeem('', 'freedom'))->toBeNull();
});

// ── Fixtures ──────────────────────────────────────────────────────

// ── Home group and GSR ────────────────────────────────────────────

test('a member carries their home group and gsr standing', function () {
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
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $groups = new InMemoryGroupRepository([new GroupStub(id: 3, title: 'Tuesday Bristol')]);

    $member = directoryPresenter($groups)->forApp(false)['members'][0];

    expect($member['group'])->toBe('Tuesday Bristol');
    expect($member['gsr'])->toBeTrue();
});

test('still no addresses travel with the new fields', function () {
    // The point of the whole class, and the fields added beside the
    // name must not quietly become a way round it.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            homeGroup: 3,
            isGSR: true,
            personalEmail: DIRECTORY_MEMBER,
            mobileNumber: '07700 900123',
        ),
    ]);

    $encoded = (string) json_encode(
        directoryPresenter(new InMemoryGroupRepository([new GroupStub(id: 3, title: 'Tuesday Bristol')]))
            ->forApp(false),
    );

    expect($encoded)->not->toContain(DIRECTORY_MEMBER);
    expect($encoded)->not->toContain('07700');
});

test('a member with no home group gets an empty one', function () {
    // Ordinary rather than exceptional: a member need not have a
    // group recorded, and a group can be deleted while members still
    // point at it. The app leaves the line out.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            homeGroup: 99,
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $member = directoryPresenter(new InMemoryGroupRepository([]))->forApp(false)['members'][0];

    expect($member['group'])->toBe('');
    expect($member['gsr'])->toBeFalse();
});

test('the directory still builds with no group repository at all', function () {
    // Unity ships headless and need not have groups bound. Absent,
    // the list is built without home groups rather than not at all.
    $member = directoryPresenter()->forApp(false)['members'][0];

    expect($member['group'])->toBe('');
    expect($member)->toHaveKey('name');
});

// ── Intergroup service position ───────────────────────────────────

test('a member carries their intergroup service position', function () {
    // Somebody writing to the Secretary is looking for a job rather
    // than a name, and has no way to tell which of these people holds
    // it from a first name and a home group.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            intergroupPosition: 855,
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $positions = new InMemoryPositionRepository([
        new PositionStub(id: 855, longName: 'Intergroup Secretary'),
    ]);

    $member = directoryPresenter(positions: $positions)->forApp(false)['members'][0];

    expect($member['position'])->toBe('Intergroup Secretary');
});

test('a member holding no position gets an empty one', function () {
    // The ordinary case by a distance: most of the fellowship holds
    // no intergroup position at all.
    $member = directoryPresenter(positions: new InMemoryPositionRepository([]))
        ->forApp(false)['members'][0];

    expect($member['position'])->toBe('');
});

test('a position that cannot be named is left empty rather than guessed', function () {
    // A position can be deleted while members still point at it.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            intergroupPosition: 404,
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $member = directoryPresenter(positions: new InMemoryPositionRepository([]))
        ->forApp(false)['members'][0];

    expect($member['position'])->toBe('');
});

test('the directory still builds with no position repository at all', function () {
    // Feature-detected exactly as groups are, and for the same
    // reason: a headless Unity need not have positions bound.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            intergroupPosition: 855,
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $member = directoryPresenter()->forApp(false)['members'][0];

    expect($member['position'])->toBe('');
    expect($member)->toHaveKey('name');
});

test('no address travels with the position either', function () {
    // A Position carries an email of its own — the role's, not the
    // member's, but an address all the same, and this class hands out
    // none of either sort.
    $this->members = new InMemoryMemberRepository([
        new MemberStub(
            id: 7,
            anonymousName: 'Dave P',
            showMemberProfile: true,
            intergroupPosition: 855,
            personalEmail: DIRECTORY_MEMBER,
        ),
    ]);

    $positions = new InMemoryPositionRepository([
        new PositionStub(id: 855, longName: 'Intergroup Secretary', email: 'secretary@example.org'),
    ]);

    $encoded = (string) json_encode(directoryPresenter(positions: $positions)->forApp(false));

    expect($encoded)->not->toContain('secretary@example.org');
    expect($encoded)->not->toContain(DIRECTORY_MEMBER);
});

// ── Whether a member has a device ─────────────────────────────────

test('a member with a live device on Firebase is marked as having one', function () {
    // The app lets a member be chosen only when this is true.
    $this->withLink = [7];

    $members = directoryPresenter()->forApp(false)['members'];

    expect(array_column($members, 'hasDevice'))->toBe([true, false]);
});

test('a member with no device is still listed', function () {
    // Listed and flagged, not left out: the address book keeps its
    // shape as people enrol and drop off.
    $members = directoryPresenter()->forApp(false)['members'];

    expect(array_column($members, 'name'))->toBe(['Dave P', 'Sue M']);
    expect(array_column($members, 'hasDevice'))->toBe([false, false]);
});

test('when Firebase cannot be asked, everyone can be chosen', function () {
    // Unknown isn't nobody: greying out the whole address book would stop
    // anyone trying, and a send still reports who it couldn't reach.
    $this->withLink = null;

    $members = directoryPresenter()->forApp(false)['members'];

    expect(array_column($members, 'hasDevice'))->toBe([true, true]);
});

function directoryPresenter(
    ?InMemoryGroupRepository $groups = null,
    ?InMemoryPositionRepository $positions = null,
): DirectoryPresenter {
    return new DirectoryPresenter(
        test()->members,
        new InMemoryCommitteeRepository(),
        new MemberGate(test()->members),
        $groups,
        $positions,
        test()->withLink === null ? null : MembersWithLink::of(...test()->withLink),
    );
}

function directoryController(): DirectoryController
{
    return new DirectoryController(
        directoryPresenter(),
        test()->settings,
        test()->audit,
    );
}

function directoryRequest(string $token = ''): WP_REST_Request
{
    $request = new WP_REST_Request();

    if ($token !== '') {
        $request->set_header('authorization', 'Bearer ' . $token);
    }

    return $request;
}
