<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\MessageController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use RuntimeException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The message surface a handset talks to.
 *
 * <b>Two properties carry most of the weight here, and neither is
 * visible from the outside.</b>
 *
 * The inbox hands back <i>sealed</i> envelopes and nothing else. The
 * bodies are stored in plain text and this server can read them — that is
 * a documented decision, and what makes the admin log and the audit
 * possible — but nothing readable may cross the wire, because the wire is
 * where an intercepted response would be somebody's messages.
 *
 * And a handset only ever sees its own. Every read is scoped to the
 * member behind the bearer token, so naming somebody else's message
 * answers exactly as naming one that does not exist.
 */

covers(\Fellowship\Rest\MessageController::class);

const MESSAGE_CONTROLLER_MEMBER = 'member@example.org';

const MESSAGE_CONTROLLER_OTHER = 'other@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('wp_generate_uuid4')->alias(static fn(): string => '1111-' . random_int(1, 999999999));

    $this->devices = new InMemoryDeviceRepository();
    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->minter = new DeviceTokenMinter();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: MESSAGE_CONTROLLER_MEMBER),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: MESSAGE_CONTROLLER_OTHER),
    ]);

    [$this->publicKey, $this->privateKey] = messageControllerKeypair();
});

// ── The inbox ─────────────────────────────────────────────────────

test('an empty inbox is not an error', function () {
    $token = messageControllerEnrol();

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['messages'])->toBe([]);
});

test('the inbox hands back sealed envelopes and nothing else', function () {
    // The assertion that matters: the subject and body must not
    // appear anywhere in the response.
    $token = messageControllerEnrol();
    giveMessage('Intergroup moved', 'Now the 14th, same room.');

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $data = (array) $response->get_data();
    expect($data['messages'])->toHaveCount(1);
    expect($data['messages'][0])->toHaveKey('k');
    expect($data['messages'][0])->toHaveKey('p');

    $encoded = (string) json_encode($data);
    expect($encoded)->not->toContain('Intergroup moved');
    expect($encoded)->not->toContain('same room');
});

test('a handset only sees its own messages', function () {
    $token = messageControllerEnrol();

    // Addressed to somebody else entirely.
    $message = $this->messages->create(
        'uuid-2',
        'sender@example.org',
        9,
        'Sender',
        'Not for you',
        'Private.',
        'members',
        '',
        1788000000,
        0,
        0,
    );
    $this->recipients->addMany($message->id, [['email' => MESSAGE_CONTROLLER_OTHER, 'member_id' => 8]], 1788000000);

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['messages'])->toBe([]);
});

test('the poll only returns what the handset does not hold', function () {
    $token = messageControllerEnrol();
    giveMessage('First', 'One.');
    $second = giveMessage('Second', 'Two.');

    $response = messageControllerController()->inbox(messageControllerRequest(['since' => $second - 1], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['messages'])->toHaveCount(1);
});

test('the unread count comes back with the inbox', function () {
    $token = messageControllerEnrol();
    giveMessage('First', 'One.');
    giveMessage('Second', 'Two.');

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['unread'])->toBe(2);
});

test('a message that cannot be sealed is omitted rather than fatal', function () {
    // A handset whose stored key has gone. It sees a short inbox and
    // a 200, and reports the fault separately — better than a 500
    // that takes every other message with it.
    $token = enrolWithKey('not-a-key');
    giveMessage('Intergroup moved', 'Now the 14th.');

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['messages'])->toBe([]);
});

test('an unauthenticated inbox is refused', function () {
    expect(messageControllerController()->inbox(messageControllerRequest([])))->toBeInstanceOf(WP_Error::class);
});

test('a revoked handset gets no inbox', function () {
    $token = messageControllerEnrol();
    $this->devices->revoke(1, time());

    expect(messageControllerController()->inbox(messageControllerRequest([], $token)))->toBeInstanceOf(WP_Error::class);
});

// ── Marking read ──────────────────────────────────────────────────

test('marking read lowers the unread count', function () {
    $token = messageControllerEnrol();
    $id = giveMessage('Intergroup moved', 'Now the 14th.');

    $response = messageControllerController()->markRead(messageControllerRequest(['id' => $id], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['unread'])->toBe(0);
});

test('marking somebody elses message read is a not found', function () {
    // Indistinguishable from a message that does not exist, which is
    // the point: naming another member's message must not confirm it
    // is there.
    $token = messageControllerEnrol();

    $message = $this->messages->create(
        'uuid-3',
        'sender@example.org',
        9,
        'Sender',
        'Not for you',
        'Private.',
        'members',
        '',
        1788000000,
        0,
        0,
    );
    $this->recipients->addMany($message->id, [['email' => MESSAGE_CONTROLLER_OTHER, 'member_id' => 8]], 1788000000);

    $response = messageControllerController()->markRead(messageControllerRequest(['id' => $message->id], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

test('marking a message that does not exist is the same refusal', function () {
    $token = messageControllerEnrol();

    $response = messageControllerController()->markRead(messageControllerRequest(['id' => 999], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

// ── Receipts ──────────────────────────────────────────────────────

test('a handset says which messages it has opened', function () {
    $token = messageControllerEnrol();
    $id = giveMessage('Intergroup moved', 'Now the 14th.');

    $response = messageControllerController()->markReceived(messageControllerRequest(['ids' => [$id]], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->recipients->forMessage($id)[0]->receivedAt)->not->toBeNull();
});

test('the ids may arrive as a comma separated list', function () {
    // WordPress accepts either for an array argument, and a query
    // string built by hand is the likelier of the two.
    $token = messageControllerEnrol();
    $first = giveMessage('One', 'First.');
    $second = giveMessage('Two', 'Second.');

    messageControllerController()->markReceived(messageControllerRequest(['ids' => $first . ',' . $second], $token));

    expect($this->recipients->forMessage($first)[0]->receivedAt)->not->toBeNull();
    expect($this->recipients->forMessage($second)[0]->receivedAt)->not->toBeNull();
});

test('acknowledging somebody elses message changes nothing and says nothing', function () {
    // The same "ok" as for a message of their own. Anything else would
    // let a handset learn which ids were sent to other people.
    $token = messageControllerEnrol();
    $strangers = storeFrom('sender@example.org', 'Not for you');
    $this->recipients->addMany($strangers, [['email' => MESSAGE_CONTROLLER_OTHER, 'member_id' => 8]], 1788000000);

    $response = messageControllerController()->markReceived(messageControllerRequest(['ids' => [$strangers]], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['ok'])->toBeTrue();
    expect($this->recipients->forMessage($strangers)[0]->receivedAt)->toBeNull();
});

test('acknowledging nothing is a bad request', function () {
    $token = messageControllerEnrol();

    $response = messageControllerController()->markReceived(messageControllerRequest(['ids' => []], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_ids');
});

test('acknowledging with no token is refused', function () {
    expect(messageControllerController()->markReceived(messageControllerRequest(['ids' => [1]])))->toBeInstanceOf(WP_Error::class);
});

test('reading a message counts as receiving it', function () {
    $token = messageControllerEnrol();
    $id = giveMessage('Intergroup moved', 'Now the 14th.');

    messageControllerController()->markRead(messageControllerRequest(['id' => $id], $token));

    expect($this->recipients->forMessage($id)[0]->isReceived())->toBeTrue();
});

test('a sender is told how far their message has got', function () {
    $token = messageControllerEnrol();
    $sent = storeFrom(MESSAGE_CONTROLLER_MEMBER, 'Literature order');
    $this->recipients->addMany($sent, [
        ['email' => MESSAGE_CONTROLLER_OTHER, 'member_id' => 8],
        ['email' => 'third@example.org', 'member_id' => 9],
        ['email' => 'fourth@example.org', 'member_id' => 10],
    ], 1788000000);
    $this->recipients->markReceived([$sent], MESSAGE_CONTROLLER_OTHER, 1788000050);
    $this->recipients->markRead($sent, 'third@example.org', 1788000100);

    $response = messageControllerController()->receipts(messageControllerRequest(['ids' => [$sent]], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['receipts'])->toBe([['id' => $sent, 'recipients' => 3, 'received' => 2, 'read' => 1]]);
});

test('receipts leave out messages the member did not send', function () {
    // Left out rather than refused, so the answer cannot be used to
    // walk the id space — including for a message addressed to them.
    $token = messageControllerEnrol();
    $theirs = storeFrom(MESSAGE_CONTROLLER_OTHER, 'Not yours to ask about');
    $this->recipients->addMany($theirs, [['email' => MESSAGE_CONTROLLER_MEMBER, 'member_id' => 7]], 1788000000);

    $response = messageControllerController()->receipts(messageControllerRequest(['ids' => [$theirs, 999]], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['receipts'])->toBe([]);
});

test('receipts carry nothing of the message itself', function () {
    $token = messageControllerEnrol();
    $sent = storeFrom(MESSAGE_CONTROLLER_MEMBER, 'Secretary report');
    $this->recipients->addMany($sent, [['email' => MESSAGE_CONTROLLER_OTHER, 'member_id' => 8]], 1788000000);

    $response = messageControllerController()->receipts(messageControllerRequest(['ids' => [$sent]], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    $encoded = (string) json_encode($response->get_data());
    expect($encoded)->not->toContain('Secretary report');
    expect($encoded)->not->toContain(MESSAGE_CONTROLLER_OTHER);
});

test('receipts with no token are refused', function () {
    expect(messageControllerController()->receipts(messageControllerRequest(['ids' => [1]])))->toBeInstanceOf(WP_Error::class);
});

// ── Sending ───────────────────────────────────────────────────────

test('a handset may not address the whole fellowship', function () {
    // That is a broadcast. It belongs to whoever holds the send
    // capability in WordPress, and the app has no undo.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_audience');
});

test('a committee send is refused until the intergroup enables it', function () {
    // A handset writing to a whole committee is a decision the
    // intergroup makes, not a default it inherits.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'committee' => 'steering',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_committee_send_disabled');
});

test('a message addressed to nobody reachable is refused', function () {
    // An id the app holds that resolves to no address at all — a
    // member deleted since the address book was fetched.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [4242],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

test('member ids that are not a list are treated as none', function () {
    // The app sends JSON; a malformed body must be refused rather
    // than fatal on a foreach.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => 'seven',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

test('a member can send to another member by opaque id', function () {
    // The whole point of the address book: the app never learns an
    // address, and sends an id back for the server to resolve.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_status())->toBe(201);
});

test('too many messages from one handset are refused', function () {
    // Keyed on the device rather than the member, so one runaway
    // app cannot silence that member's other handset.
    $token = messageControllerEnrol();
    $controller = messageControllerController();

    $limited = false;

    for ($i = 0; $i < 40; $i++) {
        $response = $controller->send(messageControllerRequest([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
            $limited = true;

            break;
        }
    }

    expect($limited)->toBeTrue('The send endpoint never rate-limited a repeated handset.');
});

test('a storage failure is five hundred rather than a fatal', function () {
    $token = messageControllerEnrol();

    $response = messageControllerController(null, messageControllerThrowingMessages())->send(messageControllerRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_send_failed');
});

test('a message addressed only to its own sender reaches nobody', function () {
    // The resolver drops the sender from their own audience, so a
    // handset naming only itself resolves to an empty list. Storing
    // it would put a message in the log that nobody can ever read.
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Note to self',
        'body' => 'Remember the 14th.',
        'member_ids' => [7],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_recipients');
});

// ── Replying ──────────────────────────────────────────────────────

test('a member may reply to a message they received', function () {
    $token = messageControllerEnrol();
    $id = giveMessage('Intergroup moved', 'Now the 14th.');

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Re: Intergroup moved',
        'body' => 'Understood.',
        'member_ids' => [8],
        'reply_to' => $id,
    ], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
});

test('a member may reply to a message they sent themselves', function () {
    // Without this, answering in a thread you started would be
    // refused — which is most of a conversation.
    $token = messageControllerEnrol();
    $own = storeFrom(MESSAGE_CONTROLLER_MEMBER, 'Intergroup moved');

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Re: Intergroup moved',
        'body' => 'One more thing.',
        'member_ids' => [8],
        'reply_to' => $own,
    ], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
});

test('replying to a message that is none of theirs reads as not found', function () {
    // "Not found" rather than "not yours": answering differently
    // would let a handset walk the id space to learn what exists.
    $token = messageControllerEnrol();
    $strangers = storeFrom(MESSAGE_CONTROLLER_OTHER, 'Private');

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Re: Private',
        'body' => 'Reading over your shoulder.',
        'member_ids' => [8],
        'reply_to' => $strangers,
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

test('replying to a message that never existed reads the same', function () {
    $token = messageControllerEnrol();

    $response = messageControllerController()->send(messageControllerRequest([
        'subject' => 'Re: nothing',
        'body' => 'Hello?',
        'member_ids' => [8],
        'reply_to' => 4242,
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

// ── Marking read ──────────────────────────────────────────────────

test('marking a message read answers the remaining unread count', function () {
    // The app puts it on its badge, so it comes back from the same
    // call rather than needing a second round trip.
    $token = messageControllerEnrol();
    $id = giveMessage('Intergroup moved', 'Now the 14th.');
    giveMessage('Second', 'Also unread.');

    $response = messageControllerController()->markRead(messageControllerRequest(['id' => $id], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $data = (array) $response->get_data();

    expect($data['ok'])->toBeTrue();
    expect($data['unread'])->toBe(1);
});

test('marking somebody elses message read is not found', function () {
    $token = messageControllerEnrol();
    $strangers = storeFrom(MESSAGE_CONTROLLER_OTHER, 'Private');

    $response = messageControllerController()->markRead(messageControllerRequest(['id' => $strangers], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

test('marking read with no token is refused', function () {
    expect(messageControllerController()->markRead(messageControllerRequest(['id' => 1])))->toBeInstanceOf(WP_Error::class);
});

// ── Which refusal it was ──────────────────────────────────────────

/**
 * A handset holding a live token whose member the gate now refuses is
 * told which, because it is the only refusal a member can act on and
 * because that caller has already proved it holds one of this site's
 * credentials. Link shows it instead of "could not be reached".
 */
test('a token whose member has gone says so', function () {
    $token = enrolFor('nobody@example.test');

    $response = messageControllerController()->inbox(messageControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_not_a_member');
    expect($response->get_error_data()['status'])->toBe(403);
});

/**
 * And every other refusal stays exactly as undifferentiated as it was.
 * A caller who has proved nothing learns nothing — which is what stops
 * this endpoint being used to find out which addresses are enrolled.
 */
test('a token this site never issued is still just unauthenticated', function () {
    $response = messageControllerController()->inbox(messageControllerRequest([], $this->minter->mint()));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
    expect($response->get_error_data()['status'])->toBe(401);
});

test('a malformed token is still just unauthenticated', function () {
    $response = messageControllerController()->inbox(messageControllerRequest([], 'not-a-token'));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
});

// ── Fixtures ──────────────────────────────────────────────────────

function messageControllerController(?Settings $settings = null, ?InMemoryMessageRepository $store = null): MessageController
{
    $gate = new MemberGate(test()->members);
    $settings ??= new Settings();
    $sealer = new MessageSealer();

    return new MessageController(
        new CurrentDevice(test()->devices, test()->minter, $gate, test()->members),
        test()->messages,
        test()->recipients,
        new MessageDispatcher(
            $store ?? test()->messages,
            test()->recipients,
            test()->devices,
            // Unconfigured: no service account, so nothing is pushed
            // and the dispatcher takes its documented degraded path.
            // Push has its own tests; this is about what the REST
            // surface answers.
            new FcmTransport(new FcmClient(), $settings, $sealer),
        ),
        new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
        $sealer,
        test()->members,
        $settings,
        new RateLimiter(),
        test()->audit,
    );
}

/** Store a message from a given address, addressed to nobody in particular. */
function storeFrom(string $senderEmail, string $subject): int
{
    return test()->messages->create(
        'uuid-' . $senderEmail . '-' . $subject,
        $senderEmail,
        $senderEmail === MESSAGE_CONTROLLER_MEMBER ? 7 : 8,
        'Dave P',
        $subject,
        'Now the 14th.',
        'members',
        '',
        1788000000,
        0,
        0,
    )->id;
}

function messageControllerThrowingMessages(): InMemoryMessageRepository
{
    return new class extends InMemoryMessageRepository {
        public function create(
            string $uuid,
            string $senderEmail,
            int $senderMemberId,
            string $senderName,
            string $subject,
            string $body,
            string $audienceType,
            string $audienceRef,
            int $createdAt,
            int $replyToId,
            int $senderDeviceId,
        ): Message {
            throw new RuntimeException('The messages table is gone.');
        }
    };
}

/** Enrol a handset for the member and answer its bearer token. */
function messageControllerEnrol(): string
{
    return enrolWithKey(test()->publicKey);
}

/**
 * A device row for an address the member repository does not know —
 * a member removed from Unity, or one whose personal email was
 * changed while their handset went on holding a perfectly valid
 * token.
 */
function enrolFor(string $email): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        $email,
        7,
        'Pixel 6a',
        'android',
        test()->publicKey,
        'fcm',
        'token-1',
        1788000000,
    );

    return $token;
}

function enrolWithKey(string $publicKey): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        MESSAGE_CONTROLLER_MEMBER,
        7,
        'Pixel 6a',
        'android',
        $publicKey,
        'fcm',
        'token-1',
        1788000000,
    );

    return $token;
}

/** Address a message to the member, and answer its id. */
function giveMessage(string $subject, string $body): int
{
    $message = test()->messages->create(
        'uuid-' . $subject,
        'sender@example.org',
        9,
        'Dave B',
        $subject,
        $body,
        'members',
        '',
        1788000000,
        0,
        0,
    );

    test()->recipients->addMany($message->id, [['email' => MESSAGE_CONTROLLER_MEMBER, 'member_id' => 7]], 1788000000);

    return $message->id;
}

/**
 * @param array<string, mixed> $params
 */
function messageControllerRequest(array $params, string $token = ''): WP_REST_Request
{
    $request = new WP_REST_Request();

    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }

    if ($token !== '') {
        $request->set_header('authorization', 'Bearer ' . $token);
    }

    return $request;
}

/**
 * A real RSA-2048 keypair, as base64 SPKI and PEM private key.
 *
 * Returned rather than written onto the test case: openssl_pkey_export()
 * fills its argument by reference, and a property reached through Pest's
 * test() proxy is a copy, so the key would land nowhere.
 *
 * @return array{0: string, 1: string}
 */
function messageControllerKeypair(): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($resource === false) {
        test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $privateKey = '';
    openssl_pkey_export($resource, $privateKey);

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    return [preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '', $privateKey];
}
