<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
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
    $_POST = [];

    WpState::$userCan = true;

    when('get_current_user_id')->justReturn(3);
    when('wp_generate_uuid4')->alias(
        static fn(): string => '11111111-2222-4333-8444-555555555555'
    );

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
    ]);
});

test('a message to the whole fellowship is sent from here', function () {
    // What the app may not do. Naming no audience is the broadcast.
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th, same room.';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');
    expect($this->messages->rows)->toHaveCount(1);
    expect($this->recipients->rows)->toHaveCount(2);
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
    expect($this->messages->rows)->toBe([]);
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
    $_POST['committee'] = '';

    composeSendPage()->sendFromRequest();

    $message = array_values($this->messages->rows)[0];
    expect($message->senderMemberId)->toBe(9);
    expect($message->senderName)->toBe('Jo B');
});

test('a member who writes one does not receive it', function () {
    // What a send from the app does. Their own message arriving on
    // their phone would offer a reply addressed to themselves.
    composeSendAuthorIsMember();
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    composeSendPage()->sendFromRequest();

    expect($this->recipients->rows)->toHaveCount(2);
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

    $message = array_values($this->messages->rows)[0];
    expect($message->senderMemberId)->toBe(0);
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
    $settings = new Settings();
    $sealer = new MessageSealer();

    return new ComposePage(
        new MessageApi(
            new MessageDispatcher(
                test()->messages,
                test()->recipients,
                new InMemoryDeviceRepository(),
                new FcmTransport(new FcmClient(), $settings, $sealer),
            ),
            new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
            test()->audit,
        ),
        new InMemoryCommitteeRepository(),
        $gate,
    );
}
