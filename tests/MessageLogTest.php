<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\MessagesPage;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_REST_Request;

/**
 * The admin message log, and who the server thinks is calling.
 *
 * <b>The log is the reason message bodies are stored readable.</b> That
 * was a decision rather than an oversight — it is what makes an admin
 * composing to a committee, this screen, and Scrutiny's audit possible at
 * all — so what the screen shows about each message is the visible half
 * of that trade, and the delivery counts are what make "this went
 * nowhere" noticeable.
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

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: MESSAGE_LOG_MEMBER),
    ]);
});

test('the log shows who sent what and to whom', function () {
    messageLogGive('committee', 'steering', 'Dave P');

    $markup = messageLogRender();

    expect($markup)->toContain('Intergroup moved');
    expect($markup)->toContain('Dave P');
    expect($markup)->toContain('steering');
});

test('a message from the app is marked as such', function () {
    // Which is how somebody reading the log tells a member's message
    // from one the intergroup sent.
    messageLogGive('members', '', 'Dave P', fromApp: true);

    expect(messageLogRender())->toContain('from Link');
});

test('a message with no sender reads as the intergroup', function () {
    // A send through the API has no member behind it. Showing a blank
    // sender would look like data loss.
    messageLogGive('all', '', '');

    expect(messageLogRender())->toContain('Intergroup');
});

test('the log shows how many read it', function () {
    // The half of the screen that makes "this went nowhere" visible.
    $id = messageLogGive('members', '', 'Dave P');

    $this->recipients->addMany($id, [
        ['email' => MESSAGE_LOG_MEMBER, 'member_id' => 7],
        ['email' => 'sue@example.org', 'member_id' => 8],
    ], 1788000000);
    $this->recipients->markRead($id, MESSAGE_LOG_MEMBER, 1788000100);

    expect(messageLogRender())->toContain('1 / 2');
});

test('each audience is named in words', function () {
    messageLogGive('all', '', 'Dave P');

    expect(messageLogRender())->toContain('Everyone');
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
    return captureOutput(fn() => (new MessagesPage(test()->messages, test()->recipients))->render());
}

function messageLogGive(string $audience, string $ref, string $sender, bool $fromApp = false): int
{
    return test()->messages->create(
        'uuid-' . count(test()->messages->rows),
        $sender === '' ? '' : 'dave@example.org',
        $sender === '' ? 0 : 7,
        $sender,
        'Intergroup moved',
        'Now the 14th, same room as usual.',
        $audience,
        $ref,
        1788000000,
        0,
        $fromApp ? 4 : 0,
    )->id;
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
