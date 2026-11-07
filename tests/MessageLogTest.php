<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\MessagesPage;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\LoggedMessage;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageLog;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_REST_Request;

/**
 * The admin message log, and who the server thinks is calling.
 *
 * <b>The log can't show what a message said.</b> Messages are end-to-end
 * encrypted, so it shows who sent one, the kind of audience, and how far it
 * got. The delivery counts are what make "this went nowhere" noticeable.
 *
 * <b>CurrentDevice is the single answer to "who is calling?"</b> Every
 * authenticated route runs through it, and it re-runs the member gate on
 * every request rather than trusting the token alone — so a member who
 * stops qualifying is refused on their next call rather than at their
 * next enrolment.
 */

covers(\Fellowship\Admin\MessagesPage::class, \Fellowship\Devices\CurrentDevice::class);

const MESSAGE_LOG_MEMBER = 'member@example.org';

beforeEach(function () {
    $_GET = [];
    WpState::$userCan = true;

    when('paginate_links')->justReturn('');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));

    $this->log = new InMemoryMessageLog();
    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: MESSAGE_LOG_MEMBER),
    ]);
});

test('the log shows who sent one and to what kind of audience', function () {
    $this->log->add(senderMemberId: 7, audience: LoggedMessage::AUDIENCE_PART);

    $markup = messageLogRender();

    expect($markup)->toContain('Dave P');
    expect($markup)->toContain('A committee or the GSRs');
});

test('the log says why it shows no message text', function () {
    $this->log->add();

    expect(messageLogRender())->toContain('end-to-end encrypted');
});

test('a message with no sender reads as the intergroup', function () {
    // A send through the API has no member behind it. Showing a blank
    // sender would look like data loss.
    $this->log->add(senderMemberId: 0);

    expect(messageLogRender())->toContain('Intergroup');
});

test('a sender whose record has gone says so', function () {
    $this->log->add(senderMemberId: 99);

    expect(messageLogRender())->toContain('no member record');
});

test('a sender with no anonymous name says so', function () {
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: ' ', personalEmail: MESSAGE_LOG_MEMBER),
    ]);
    $this->log->add(senderMemberId: 7);

    expect(messageLogRender())->toContain('unnamed member');
});

test('the log counts delivery and reading for a message to several', function () {
    // The half of the screen that makes "this went nowhere" visible.
    // Counted, because "read" of a committee message would otherwise
    // mean "read by somebody".
    $this->log->add(recipients: 3, received: 2, read: 1);

    expect(messageLogRender())->toContain('3 recipients: 2 delivered, 1 read');
});

test('a message to one member is said in a word, as Link ticks it', function (int $received, int $read, string $expected) {
    $this->log->add(recipients: 1, received: $received, read: $read);

    expect(messageLogRender())->toContain('<td>' . $expected . '</td>');
})->with([
    'not yet on a handset' => [0, 0, 'Sent'],
    'opened on a handset'  => [1, 0, 'Delivered'],
    'read'                 => [1, 1, 'Read'],
    'read with the receipt lost on the way back' => [0, 1, 'Read'],
]);

test('a message that reached nobody says so', function () {
    $this->log->add(recipients: 0);

    expect(messageLogRender())->toContain('Reached nobody');
});

test('each kind of audience is named in words', function (string $kind, string $words) {
    $this->log->add(audience: $kind);

    expect(messageLogRender())->toContain($words);
})->with([
    'everyone'     => [LoggedMessage::AUDIENCE_EVERYONE, 'Everyone'],
    'part'         => [LoggedMessage::AUDIENCE_PART, 'A committee or the GSRs'],
    'members'      => [LoggedMessage::AUDIENCE_MEMBERS, 'Named members'],
    'mixed'        => [LoggedMessage::AUDIENCE_MIXED, 'Named members and a committee or the GSRs'],
    'not one of ours' => ['something-new', 'Unknown'],
]);

test('Firebase being out says so rather than that nothing was sent', function () {
    $this->log->down = true;

    $markup = messageLogRender();

    expect($markup)->toContain('could not be reached');
    expect($markup)->not->toContain('No messages have been sent');
});

test('the log asks for one more than a page, to know if there is a next one', function () {
    for ($i = 0; $i < 26; $i++) {
        $this->log->add();
    }

    expect(substr_count(messageLogRender(), '<tr>'))->toBe(26);
});

// ── Who is calling ────────────────────────────────────────────────

test('an enrolled handset is recognised', function () {
    $token = messageLogEnrol();

    $device = messageLogCurrentDevice()->fromRequest(messageLogRequest($token));

    expect($device)->not->toBeNull();
    expect($device->memberEmail)->toBe(MESSAGE_LOG_MEMBER);
});

test('a request with no header is nobody', function () {
    expect(messageLogCurrentDevice()->fromRequest(messageLogRequest()))->toBeNull();
});

test('something that is not a token is nobody', function () {
    // Refused on shape before it ever reaches the database, so a
    // malformed header costs no query.
    expect(messageLogCurrentDevice()->fromRequest(messageLogRequest('not-a-token')))->toBeNull();
});

test('a revoked handset is nobody', function () {
    $token = messageLogEnrol();
    $this->devices->revoke(1, time());

    expect(messageLogCurrentDevice()->fromRequest(messageLogRequest($token)))->toBeNull();
});

test('a member who no longer qualifies is refused on their next call', function () {
    // The gate is re-run on every request rather than trusted from
    // enrolment, so somebody removed from Unity stops being able to
    // call immediately rather than at their next sign-in.
    $token = messageLogEnrol();

    $this->members = new InMemoryMemberRepository([]);

    expect(messageLogCurrentDevice()->fromRequest(messageLogRequest($token)))->toBeNull();
});

test('the member behind a device is resolved through the same gate', function () {
    // So the answer cannot disagree with whether the request was
    // allowed at all.
    $token = messageLogEnrol();
    $current = messageLogCurrentDevice();

    $device = $current->fromRequest(messageLogRequest($token));

    expect($device)->not->toBeNull();
    expect($current->memberFor($device))->not->toBeNull();
});

// ── Fixtures ──────────────────────────────────────────────────────

function messageLogRender(): string
{
    return captureOutput(fn() => (new MessagesPage(test()->log, test()->members))->render());
}

function messageLogCurrentDevice(): CurrentDevice
{
    $gate = new MemberGate(test()->members);

    return new CurrentDevice(test()->devices, test()->minter, $gate, test()->members);
}

function messageLogEnrol(): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        MESSAGE_LOG_MEMBER,
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

function messageLogRequest(string $token = ''): WP_REST_Request
{
    $request = new WP_REST_Request();

    if ($token !== '') {
        $request->set_header('authorization', 'Bearer ' . $token);
    }

    return $request;
}
