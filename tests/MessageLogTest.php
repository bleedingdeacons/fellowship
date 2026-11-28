<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\MessagesPage;
use Fellowship\Messaging\LoggedMessage;
use Fellowship\Tests\Support\InMemoryMessageLog;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * The admin message log.
 *
 * <b>The log can't show what a message said.</b> Messages are end-to-end
 * encrypted, so it shows who sent one, the kind of audience, and how far it
 * got. The delivery counts are what make "this went nowhere" noticeable.
 */

covers(\Fellowship\Admin\MessagesPage::class);

const MESSAGE_LOG_MEMBER = 'member@example.org';

beforeEach(function () {
    $_GET = [];
    WpState::$userCan = true;

    when('paginate_links')->justReturn('');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));

    $this->log = new InMemoryMessageLog();

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

// ── Fixtures ──────────────────────────────────────────────────────

function messageLogRender(): string
{
    return captureOutput(fn() => (new MessagesPage(test()->log, test()->members))->render());
}
