<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
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

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->audit = new SpyAuditLogger();
    $this->devices = new InMemoryDeviceRepository();
    $this->committees = new InMemoryCommitteeRepository();
    $this->settings = new Settings();

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

// ── To one member ─────────────────────────────────────────────────

test('one member is sent to by their id', function () {
    // The id the directory hands out, and the only thing the form
    // carries. The address is found on the far side of MessageApi.
    $_POST['audience'] = 'member:8';
    $_POST['subject'] = 'Your rota';
    $_POST['body'] = 'Can you take Tuesday?';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');

    $message = array_values($this->messages->rows)[0];
    expect($message->audienceType)->toBe('members');

    $recipients = array_values($this->recipients->rows);
    expect($recipients)->toHaveCount(1);
    expect($recipients[0]->memberId)->toBe(8);
    expect($recipients[0]->memberEmail)->toBe('sue@example.org');
});

test('a message to one member is sealed and pushed to their handset as the app would push it', function () {
    // The same dispatcher, sealer and FCM transport a handset's send goes
    // through. One RSA key stands in for both the service account and
    // the handset, as in AdminBranchesTest: a fake key would stop the
    // push before the first HTTP call and assert nothing.
    $pem = composeSendPrivateKey();
    $this->settings->setFcmServiceAccount((string) wp_json_encode([
        'type'         => 'service_account',
        'project_id'   => 'intergroup-fellowship',
        'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
        'private_key'  => $pem,
        'token_uri'    => 'https://oauth2.googleapis.com/token',
    ]));
    $this->devices->create('hash-8', 'sue@example.org', 8, 'Pixel 6a', 'android', composeSendPublicKey($pem), 'fcm', 'token-8', 1788000000);

    FakeWpHttp::reset();
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    $_POST['audience'] = 'member:8';
    $_POST['subject'] = 'Your rota';
    $_POST['body'] = 'Can you take Tuesday?';

    expect(composeSendPage()->sendFromRequest())->toBe('sent');
    expect(array_values($this->recipients->rows)[0]->pushedAt)->not->toBeNull();

    // The push carries the hybrid envelope's two fields and none of the
    // message in the clear.
    $push = (string) (FakeWpHttp::sentArgs(1)['body'] ?? '');
    expect($push)->toContain('token-8');
    expect($push)->toContain('"k"');
    expect($push)->toContain('"p"');
    expect($push)->not->toContain('Can you take Tuesday?');
    expect($push)->not->toContain('Your rota');
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
    expect(array_values($this->messages->rows)[0]->audienceRef)->toBe('steering');
    expect(array_values($this->recipients->rows)[0]->memberId)->toBe(7);
});

test('an audience the form does not offer is refused rather than sent to everyone', function (string $audience) {
    // Everyone is the one send that must only happen on purpose, so
    // nothing falls back to it.
    $_POST['audience'] = $audience;
    $_POST['subject'] = 'Intergroup moved';
    $_POST['body'] = 'Now the 14th.';

    expect(composeSendPage()->sendFromRequest())->toBe('error');
    expect($this->messages->rows)->toBe([]);
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
    expect($this->messages->rows)->toBe([]);
    expect($this->recipients->rows)->toBe([]);
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

function composeSendPrivateKey(): string
{
    static $pem = null;

    if ($pem === null) {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        expect($resource)->not->toBeFalse();

        openssl_pkey_export($resource, $pem);
    }

    return (string) $pem;
}

/** The SPKI body a handset sends at enrolment, without PEM armour. */
function composeSendPublicKey(string $pem): string
{
    $details = openssl_pkey_get_details(openssl_pkey_get_private($pem));
    expect($details)->toBeArray();

    return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
}

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
    $settings = test()->settings;
    $sealer = new MessageSealer();

    return new ComposePage(
        new MessageApi(
            new MessageDispatcher(
                test()->messages,
                test()->recipients,
                test()->devices,
                new FcmTransport(new FcmClient(), $settings, $sealer),
            ),
            new RecipientResolver(test()->members, test()->committees, $gate),
            test()->audit,
        ),
        test()->committees,
        $gate,
        new DirectoryPresenter(test()->members, test()->committees, $gate, test()->devices),
    );
}
