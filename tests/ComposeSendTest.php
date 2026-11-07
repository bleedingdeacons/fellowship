<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\RecordingDelivery;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * Sending from the admin compose screen.
 *
 * <b>This is the broadcast path</b> — the one a handset is deliberately
 * refused. Whoever holds the send capability can address the whole
 * fellowship from here, and there is no undo, so what the screen does
 * with a refusal matters as much as what it does with a success.
 *
 * A refusal's reason waits in a one-shot per-user transient rather than
 * travelling in the query string. A server-supplied message rendered out
 * of a URL is a reflected-content problem however carefully it is
 * escaped, and it was fixed that way once already.
 */

covers(\Fellowship\Admin\ComposePage::class);

beforeEach(function () {
    // Everyone is a choice the form makes, never a fall-back. The tests
    // about subject, body and authorship make it; the ones about the
    // audience overwrite it.
    $_POST = ['audience' => 'everyone'];

    WpState::$userCan = true;

    when('get_current_user_id')->justReturn(3);
    when('wp_generate_uuid4')->alias(
        static fn(): string => '11111111-2222-4333-8444-555555555555'
    );

    $this->delivery = new RecordingDelivery();
    $this->audit = new SpyAuditLogger();
    $this->devices = new InMemoryDeviceRepository();
    $this->committees = new InMemoryCommitteeRepository();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
    ]);
});

test('a message to the whole fellowship is sent from here', function () {
    // What the app may not do.
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th, same room.';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');
    expect($this->delivery->delivered)->toHaveCount(1);
    expect($this->delivery->resolved[0]['everyone'])->toBeTrue();
});

test('sending is audited', function () {
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    composeSendPage()->sendFromRequest();

    expect($this->audit->entries)->not->toBeEmpty();
});

test('a message with no subject is refused', function () {
    $_POST['subject'] = '';
    $_POST['body'] = 'Now the 14th.';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
    expect($this->delivery->delivered)->toBe([]);
});

test('a message with no body is refused', function () {
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = '';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
});

test('the reason waits in a transient rather than the query string', function () {
    // A server-supplied message rendered out of a URL is a
    // reflected-content problem however carefully it is escaped.
    $_POST['subject'] = '';
    $_POST['body'] = '';

    composeSendPage()->sendFromRequest();

    // The constant is private, so the assertion is that *something*
    // was stored for this user rather than that a particular key was:
    // naming the key here would only restate the implementation.
    expect(WpState::$transients)->not->toBe([]);

    $stored = implode('|', array_map('strval', WpState::$transients));

    expect($stored)->not->toBe('');
});

test('a refused send writes no audit entry', function () {
    $_POST['subject'] = '';
    $_POST['body'] = '';

    composeSendPage()->sendFromRequest();

    expect($this->audit->entries)->toBe([]);
});

test('a message from a member is credited to them', function () {
    // The signed-in user's WordPress email is a member's, so the message
    // goes out under that member's name and id. The id is what lets a
    // reply from the app be addressed straight back to them.
    composeSendAuthorIsMember();
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    composeSendPage()->sendFromRequest();

    expect($this->delivery->delivered[0]['audience']['senderMemberId'])->toBe(9);
});

test('a member\'s send is audited against them', function () {
    composeSendAuthorIsMember();
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    composeSendPage()->sendFromRequest();

    expect($this->audit->entries[0]['entityId'])->toBe(9);
});

test('a user who is not a member still sends as the intergroup', function () {
    // Nobody to credit, and nobody for a reply to go back to.
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    composeSendPage()->sendFromRequest();

    expect($this->delivery->delivered[0]['audience']['senderMemberId'])->toBe(0);
    expect($this->audit->entries[0]['entityId'])->toBe(0);
});

test('the screen says who the message will be from', function () {
    when('submit_button')->justReturn(null);

    composeSendAuthorIsMember();

    expect(captureOutput(fn() => composeSendPage()->render()))->toContain('Sent as Jo B');
});

test('the screen says when it will not be from a member', function () {
    when('submit_button')->justReturn(null);

    expect(captureOutput(fn() => composeSendPage()->render()))->toContain('Sent from the intergroup');
});

// ── To one member ─────────────────────────────────────────────────

test('one member is sent to by their id', function () {
    // The id the directory hands out, and the only thing the form carries.
    $_POST['audience'] = 'member:8';
    $_POST['subject'] = 'Your rota';
    $_POST['body'] = 'Can you take Tuesday?';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');
    expect($this->delivery->resolved[0]['memberIds'])->toBe([8]);
    expect($this->delivery->resolved[0])->not->toHaveKey('everyone');
    expect($this->audit->entries[0]['detail'])->toContain('audience:members');
});

test('what leaves is sealed, with none of the message in the clear', function () {
    $_POST['audience'] = 'member:8';
    $_POST['subject'] = 'Your rota';
    $_POST['body'] = 'Can you take Tuesday?';

    composeSendPage()->sendFromRequest();

    $sent = (string) wp_json_encode($this->delivery->delivered[0]);

    expect($sent)->toContain('"k"');
    expect($sent)->toContain('"p"');
    expect($sent)->not->toContain('Can you take Tuesday?');
    expect($sent)->not->toContain('Your rota');
});

test('a committee is sent to', function () {
    $this->committees = new InMemoryCommitteeRepository(
        [new CommitteeStub(id: 2, slug: 'steering', name: 'Steering')],
        ['steering' => [7]],
    );
    $_POST['audience'] = 'committee:steering';
    $_POST['subject'] = 'Agenda';
    $_POST['body'] = 'Attached.';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');
    expect($this->delivery->resolved[0]['committees'])->toBe(['steering']);
});

test('a refusal from Firebase reaches the screen in its own words', function () {
    $this->delivery->resolveFailure = new FirebaseUnavailable('Refused.', 'fellowship_no_reachable_members', 'None of those members have Link yet.');
    $_POST['subject'] = 'Agenda';
    $_POST['body'] = 'Attached.';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
    expect(implode('|', array_map('strval', WpState::$transients)))->toContain('None of those members have Link yet.');
});

test('an audience the form does not offer is refused rather than sent to everyone', function (string $audience) {
    // Everyone is the one send that must only happen on purpose, so
    // nothing falls back to it.
    $_POST['audience'] = $audience;
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
    expect($this->delivery->resolved)->toBe([]);
    expect($this->audit->entries)->toBe([]);
})->with(['', 'nobody', 'member:', 'member:0', 'member:-8', 'member:eight', 'committee:']);

test('a member whose record has gone is refused rather than sent to everyone', function () {
    // An id that resolves to nobody leaves a request naming nobody,
    // and a request naming nobody is the broadcast. It is stopped
    // before the request is built.
    $_POST['audience'] = 'member:99';
    $_POST['subject'] = 'Your rota';
    $_POST['body'] = 'Can you take Tuesday?';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
    expect($this->delivery->resolved)->toBe([]);
});

test('members are offered from the app address book, by name and never by address', function () {
    composeSendListedMembers();

    $markup = captureOutput(fn() => composeSendPage()->render());

    expect($markup)->toContain('value="member:8"');
    expect($markup)->toContain('Sue M');
    expect($markup)->not->toContain('sue@example.org');
});

test('a member with no Link device is shown but cannot be chosen', function () {
    // As in the app: a message to them would wait unread with nothing
    // to say so.
    composeSendListedMembers();

    $markup = captureOutput(fn() => composeSendPage()->render());

    expect($markup)->toContain('value="member:7" disabled');
    expect($markup)->toContain('Dave P (no Link device)');
    expect($markup)->not->toContain('value="member:8" disabled');
});

test('a member with their profile hidden is still offered', function () {
    // showMemberProfile plays no part in messaging.
    composeSendListedMembers();

    expect(captureOutput(fn() => composeSendPage()->render()))->toContain('Hidden H');
});

test('the signed-in member is not offered to themselves', function () {
    // They would be excluded from their own message, and it would reach
    // nobody.
    composeSendListedMembers(withAuthor: true);

    $markup = captureOutput(fn() => composeSendPage()->render());

    expect($markup)->toContain('Sent as Jo B');
    expect($markup)->not->toContain('value="member:9"');
});

/**
 * Members as the directory lists them: Sue with a handset, Dave without,
 * and one with their profile hidden. Optionally the signed-in
 * user as a listed member too.
 */
function composeSendListedMembers(bool $withAuthor = false): void
{
    when('submit_button')->justReturn(null);

    $members = [
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', showMemberProfile: true, personalEmail: 'sue@example.org'),
        new MemberStub(id: 10, anonymousName: 'Hidden H', showMemberProfile: false, personalEmail: 'hidden@example.org'),
    ];

    if ($withAuthor) {
        $members[] = new MemberStub(id: 9, anonymousName: 'Jo B', showMemberProfile: true, personalEmail: (new \WP_User())->user_email);
        test()->devices->create('hash-9', (new \WP_User())->user_email, 9, 'iPhone', 'ios', 'spki', 'fcm', 'token-9', 1788000000);
    }

    test()->members = new InMemoryMemberRepository($members);
    test()->devices->create('hash-8', 'sue@example.org', 8, 'Pixel 6a', 'android', 'spki', 'fcm', 'token-8', 1788000000);
}

/**
 * Make the signed-in user a member. wp-mocks' current user has a fixed
 * email, so the member is given that address rather than the user being
 * given another.
 */
function composeSendAuthorIsMember(): void
{
    test()->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
        new MemberStub(id: 9, anonymousName: 'Jo B', personalEmail: (new \WP_User())->user_email),
    ]);
}

function composeSendPage(): ComposePage
{
    $gate = new MemberGate(test()->members);

    return new ComposePage(
        new MessageApi(
            test()->delivery,
            new MessageSealer(),
            new RecipientResolver(test()->members, test()->committees, $gate),
            test()->members,
            test()->audit,
        ),
        test()->committees,
        $gate,
        new DirectoryPresenter(test()->members, test()->committees, $gate, test()->devices),
    );
}
