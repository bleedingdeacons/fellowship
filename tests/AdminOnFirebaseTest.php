<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Firebase\AdminFunctions;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Firebase\FirestoreLinkDevices;
use Fellowship\Firebase\FirestoreMessageLog;
use Fellowship\Firebase\GoogleTokens;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\ServiceAccount;
use Fellowship\Tests\Support\RecordingDelivery;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;

/**
 * What the admin screens now stand on.
 *
 * Sending is the part that matters most: a message has to reach a handset in the shape
 * the handset opens, and nothing may turn a send into a broadcast by accident. So the
 * envelopes are opened here with the private key and read, rather than assumed.
 */

covers(
    MessageApi::class,
    AdminFunctions::class,
    FirestoreClient::class,
    FirestoreLinkDevices::class,
    FirestoreMessageLog::class,
);

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();
    when('is_ssl')->justReturn(true);
    when('wp_generate_uuid4')->justReturn('11111111-2222-4333-8444-555555555555');
    when('get_bloginfo')->justReturn('Bristol Intergroup');

    $this->delivery = new RecordingDelivery();
    $this->audit = new SpyAuditLogger();
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
    ]);

    $this->account = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => 'fellowship-510917',
        'client_email' => 'functions@fellowship-510917.iam.gserviceaccount.com',
        'private_key'  => RecordingDelivery::privateKey(),
    ]));
    $this->tokens = new GoogleTokens();
    $this->firestore = new FirestoreClient(fn() => test()->account, $this->tokens);
    $this->functions = new AdminFunctions(fn() => test()->account, $this->tokens);
});

// ── Who a send is for ────────────────────────────────────────────

test('everyone is asked for only when nobody was named', function () {
    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($this->delivery->resolved[0])->toBe(['senderMemberId' => 0, 'everyone' => true]);
});

test('named members go by id, and the far side is never told an address', function () {
    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B', 'member_ids' => [8]]);

    expect($this->delivery->resolved[0])->toBe(['senderMemberId' => 0, 'memberIds' => [8]]);
});

test('addresses a caller already holds are turned into ids', function () {
    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B', 'member_emails' => ['SUE@example.org']]);

    expect($this->delivery->resolved[0]['memberIds'])->toBe([8]);
});

test('an address nobody holds can never become everyone', function () {
    // The most dangerous way this could go wrong. The audience names nobody, and the
    // far side refuses it.
    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B', 'member_emails' => ['stranger@example.org']]);

    expect($this->delivery->resolved[0])->not->toHaveKey('everyone');
    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_no_audience');
    expect($this->delivery->delivered)->toBe([]);
});

test('committees and the GSRs travel separately', function () {
    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B', 'committees' => ['steering'], 'gsrs' => true]);

    expect($this->delivery->resolved[0]['committees'])->toBe(['steering']);
    expect($this->delivery->resolved[0]['gsrs'])->toBeTrue();
});

test('the author is excluded and credited by id', function () {
    $author = new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org');

    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B'], $author);

    expect($this->delivery->resolved[0]['senderMemberId'])->toBe(7);
    expect($this->delivery->delivered[0]['audience']['senderMemberId'])->toBe(7);
});

test('the same audience is resolved and delivered, so the far side can compare', function () {
    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B', 'member_ids' => [8]]);

    expect($this->delivery->delivered[0]['audience'])->toBe($this->delivery->resolved[0]);
});

// ── What a handset opens ─────────────────────────────────────────

test('the envelope opens to what a handset sends itself', function () {
    $id = adminOnFirebaseApi()->send(['subject' => 'Your rota', 'body' => 'Can you take Tuesday?', 'member_ids' => [8]]);

    $envelope = $this->delivery->delivered[0]['envelopes'][0];

    expect($envelope['deviceId'])->toBe('d_sue');
    expect($id)->toBe($this->delivery->delivered[0]['id']);

    $opened = adminOnFirebaseOpen($envelope);

    expect($opened['id'])->toBe($id);
    expect($opened['subject'])->toBe('Your rota');
    expect($opened['body'])->toBe('Can you take Tuesday?');
    expect($opened['sender'])->toBe('Bristol Intergroup');
    expect($opened['sender_id'])->toBe(0);
    expect($opened['created_at'])->toBe(intdiv(intdiv($id, 1024), 1000));
    expect($opened['uuid'])->toBe('11111111-2222-4333-8444-555555555555');
    expect($opened['reply_to'])->toBe(0);
});

test('a member\'s message is sealed under their name and id', function () {
    // A phone refuses a message whose sealed sender differs from who sent it.
    $author = new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org');

    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B'], $author);

    $opened = adminOnFirebaseOpen($this->delivery->delivered[0]['envelopes'][0]);

    expect($opened['sender'])->toBe('Dave P');
    expect($opened['sender_id'])->toBe(7);
});

test('nothing readable leaves in the envelope', function () {
    adminOnFirebaseApi()->send(['subject' => 'Your rota', 'body' => 'Can you take Tuesday?']);

    $sent = (string) json_encode($this->delivery->delivered[0]);

    expect($sent)->not->toContain('Your rota');
    expect($sent)->not->toContain('Can you take Tuesday?');
});

test('each device gets its own envelope', function () {
    $this->delivery->devices[] = ['deviceId' => 'd_two', 'publicKey' => RecordingDelivery::publicKey()];

    adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    $envelopes = $this->delivery->delivered[0]['envelopes'];

    expect(array_column($envelopes, 'deviceId'))->toBe(['d_sue', 'd_two']);
    expect($envelopes[0]['k'])->not->toBe($envelopes[1]['k']);
});

test('a key that cannot be used stops the send rather than missing somebody', function () {
    $this->delivery->devices[] = ['deviceId' => 'd_bad', 'publicKey' => 'not a key'];

    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_unusable_key');
    expect($this->delivery->delivered)->toBe([]);
    expect($this->audit->entries)->toBe([]);
});

// ── When it goes wrong ───────────────────────────────────────────

test('an audience that moved is sealed again under a new id', function () {
    $this->delivery->deliverFailures = [new FirebaseUnavailable('Moved.', 'fellowship_stale_audience', 'It changed.')];

    $id = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($this->delivery->resolved)->toHaveCount(2);
    expect($this->delivery->delivered)->toHaveCount(1);
    expect($id)->toBe($this->delivery->delivered[0]['id']);
    expect(adminOnFirebaseOpen($this->delivery->delivered[0]['envelopes'][0])['id'])->toBe($id);
});

test('an audience that keeps moving stops rather than trying forever', function () {
    $stale = new FirebaseUnavailable('Moved.', 'fellowship_stale_audience', 'Who this message reaches has changed.');
    $this->delivery->deliverFailures = [$stale, $stale, $stale, $stale];

    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_message())->toBe('Who this message reaches has changed.');
    expect($this->delivery->resolved)->toHaveCount(3);
});

test('a refusal is said in the Function\'s words, under its reason', function () {
    $this->delivery->resolveFailure = new FirebaseUnavailable('Refused.', 'fellowship_no_recipients', 'That message would not reach anybody.');

    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($result->get_error_code())->toBe('fellowship_no_recipients');
    expect($result->get_error_message())->toBe('That message would not reach anybody.');
});

test('Firebase being out says the message was not sent', function () {
    $this->delivery->resolveFailure = new FirebaseUnavailable('Could not reach it.');

    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($result->get_error_code())->toBe('fellowship_send_failed');
    expect($result->get_error_message())->toContain('not sent');
    expect($this->audit->entries)->toBe([]);
});

test('nobody with Link is refused without sealing anything', function () {
    $this->delivery->devices = [];

    $result = adminOnFirebaseApi()->send(['subject' => 'S', 'body' => 'B']);

    expect($result->get_error_code())->toBe('fellowship_no_reachable_members');
    expect($this->delivery->delivered)->toBe([]);
});

// ── What is kept ─────────────────────────────────────────────────

test('the audit trail records the subject and how many it reached, never the body', function () {
    adminOnFirebaseApi()->send(['subject' => 'Your rota', 'body' => 'Can you take Tuesday?', 'member_ids' => [8]]);

    $detail = $this->audit->entries[0]['detail'];

    expect($detail)->toContain('subject:Your rota');
    expect($detail)->toContain('recipients:1');
    expect($detail)->toContain('audience:members');
    expect($detail)->not->toContain('Can you take Tuesday?');
});

test('a committee\'s name stays in WordPress\'s own audit trail', function () {
    $committees = new InMemoryCommitteeRepository([new CommitteeStub(id: 2, slug: 'steering', name: 'Steering')]);

    adminOnFirebaseApi($committees)->send(['subject' => 'S', 'body' => 'B', 'committee' => 'steering']);

    expect($this->audit->entries[0]['detail'])->toContain('ref:steering');
});

// ── The Functions ────────────────────────────────────────────────

test('resolving asks adminResolve and reads what it answers', function () {
    adminOnFirebaseAnswers(200, '{"id":1837075327412518,"members":2,"reachable":1,"devices":[{"deviceId":"d_abc","memberId":8,"publicKey":"spki"}]}');

    $resolved = $this->functions->resolve(['everyone' => true]);

    expect(FakeWpHttp::sentUrl(1))->toBe('https://europe-west2-fellowship-510917.cloudfunctions.net/adminResolve');
    expect(FakeWpHttp::sentArgs(1)['body'])->toBe('{"everyone":true}');
    expect($resolved['id'])->toBe(1837075327412518);
    expect($resolved['members'])->toBe(2);
    expect($resolved['devices'])->toBe([['deviceId' => 'd_abc', 'publicKey' => 'spki']]);
});

test('delivering hands over the id and the envelopes with the audience', function () {
    adminOnFirebaseAnswers(200, '{"id":5,"reachable":3}');

    $reached = $this->functions->deliver(['everyone' => true], 5, [['deviceId' => 'd_abc', 'k' => 'K', 'p' => 'P']]);

    expect(FakeWpHttp::sentUrl(1))->toEndWith('/adminSend');
    expect(json_decode((string) FakeWpHttp::sentArgs(1)['body'], true))->toBe([
        'everyone'  => true,
        'id'        => 5,
        'envelopes' => [['deviceId' => 'd_abc', 'k' => 'K', 'p' => 'P']],
    ]);
    expect($reached)->toBe(3);
});

test('a Function\'s refusal carries its reason and its words', function () {
    adminOnFirebaseAnswers(412, '{"reason":"fellowship_stale_audience","message":"Who this message reaches has changed."}');

    try {
        $this->functions->deliver([], 5, []);
        expect(false)->toBeTrue();
    } catch (FirebaseUnavailable $e) {
        expect($e->reason)->toBe('fellowship_stale_audience');
        expect($e->refusal)->toBe('Who this message reaches has changed.');
    }
});

test('no answer at all has no reason, so nobody mistakes it for a refusal', function () {
    adminOnFirebaseAnswers(500, 'not json');

    try {
        $this->functions->resolve([]);
        expect(false)->toBeTrue();
    } catch (FirebaseUnavailable $e) {
        expect($e->reason)->toBe('');
        expect($e->refusal)->toBe('');
    }
});

test('revoking and removing each name their own Function', function () {
    adminOnFirebaseAnswers(200, '{}');
    adminOnFirebaseAnswers(200, '{}');

    $this->functions->revoke('d_abc');
    $this->functions->remove('d_abc');

    $urls = array_map(static fn(int $i): string => FakeWpHttp::sentUrl($i), range(0, FakeWpHttp::callCount() - 1));

    expect(implode(' ', $urls))->toContain('/adminRevoke');
    expect(implode(' ', $urls))->toContain('/adminRemove');
});

// ── Firestore ────────────────────────────────────────────────────

test('devices are read newest first, without keys', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"t"}');
    FakeWpHttp::pushResponse(200, (string) json_encode([
        ['readTime' => '2026-11-07T00:00:00Z'],
        ['document' => [
            'name'   => 'projects/p/databases/(default)/documents/devices/d_abc',
            'fields' => [
                'memberId'   => ['integerValue' => '7'],
                'platform'   => ['stringValue' => 'ios'],
                'label'      => ['stringValue' => 'New phone'],
                'pushToken'  => ['stringValue' => 'token'],
                'keyFault'   => ['booleanValue' => true],
                'status'     => ['stringValue' => 'live'],
                'createdAt'  => ['timestampValue' => '2026-11-07T02:23:08.551704Z'],
                'lastSeenAt' => ['nullValue' => null],
            ],
        ]],
    ]));

    $devices = (new FirestoreLinkDevices($this->firestore, $this->functions))->page(26, 25);

    expect($devices)->toHaveCount(1);
    expect($devices[0]->id)->toBe('d_abc');
    expect($devices[0]->memberId)->toBe(7);
    expect($devices[0]->label)->toBe('New phone');
    expect($devices[0]->hasPushToken)->toBeTrue();
    expect($devices[0]->keyFault)->toBeTrue();
    expect($devices[0]->revoked)->toBeFalse();
    expect($devices[0]->createdAt)->toBe(strtotime('2026-11-07T02:23:08Z'));
    expect($devices[0]->lastSeenAt)->toBe(0);

    $query = json_decode((string) FakeWpHttp::sentArgs(1)['body'], true)['structuredQuery'];

    expect($query['from'][0]['collectionId'])->toBe('devices');
    expect($query['orderBy'][0]['direction'])->toBe('DESCENDING');
    expect($query['limit'])->toBe(26);
    expect($query['offset'])->toBe(25);
    expect(array_column($query['select']['fields'], 'fieldPath'))->not->toContain('publicKey');
});

test('a device with no push token is not said to have one', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"t"}');
    FakeWpHttp::pushResponse(200, (string) json_encode([
        ['document' => ['name' => 'x/devices/d_abc', 'fields' => ['pushToken' => ['nullValue' => null], 'status' => ['stringValue' => 'revoked']]]],
    ]));

    $device = (new FirestoreLinkDevices($this->firestore, $this->functions))->page(1, 0)[0];

    expect($device->hasPushToken)->toBeFalse();
    expect($device->revoked)->toBeTrue();
});

test('one device is found by id, and a missing one is null', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"t"}');
    FakeWpHttp::pushResponse(200, '{"name":"x","fields":{"memberId":{"integerValue":"7"},"status":{"stringValue":"live"}}}');
    FakeWpHttp::pushResponse(404, '{}');

    $devices = new FirestoreLinkDevices($this->firestore, $this->functions);

    expect($devices->find('d_abc')?->memberId)->toBe(7);
    expect($devices->find('d_gone'))->toBeNull();
});

test('the log reads counts and never who received a message', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"t"}');
    FakeWpHttp::pushResponse(200, (string) json_encode([
        ['document' => [
            'name'   => 'x/messages/1837075327412518',
            'fields' => [
                'senderMemberId' => ['integerValue' => '7'],
                'audience'       => ['stringValue' => 'part'],
                'recipientCount' => ['integerValue' => '3'],
                'receivedCount'  => ['integerValue' => '2'],
                'readCount'      => ['integerValue' => '1'],
                'createdAt'      => ['timestampValue' => '2026-11-07T02:23:08Z'],
            ],
        ]],
    ]));

    $message = (new FirestoreMessageLog($this->firestore))->page(26, 0)[0];

    expect($message->id)->toBe(1837075327412518);
    expect($message->senderMemberId)->toBe(7);
    expect($message->audience)->toBe('part');
    expect([$message->recipients, $message->received, $message->read])->toBe([3, 2, 1]);

    $fields = array_column(json_decode((string) FakeWpHttp::sentArgs(1)['body'], true)['structuredQuery']['select']['fields'], 'fieldPath');

    expect($fields)->not->toContain('recipientMemberIds');
});

test('Firestore refusing a query is unavailable, never an empty list', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"t"}');
    FakeWpHttp::pushResponse(403, '{}');

    (new FirestoreMessageLog($this->firestore))->page(26, 0);
})->throws(FirebaseUnavailable::class);

test('no service account is unavailable, never an empty list', function () {
    $this->account = null;

    (new FirestoreLinkDevices($this->firestore, $this->functions))->page(26, 0);
})->throws(FirebaseUnavailable::class);

// ── Fixtures ─────────────────────────────────────────────────────

function adminOnFirebaseApi(?InMemoryCommitteeRepository $committees = null): MessageApi
{
    return new MessageApi(
        test()->delivery,
        new MessageSealer(),
        new RecipientResolver(test()->members, $committees ?? new InMemoryCommitteeRepository(), new MemberGate(test()->members)),
        test()->members,
        test()->audit,
    );
}

/** A Google ID token, then what the Function answers. */
function adminOnFirebaseAnswers(int $status, string $body): void
{
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse($status, $body);
}

/**
 * Open an envelope as a handset would.
 *
 * @param array{deviceId: string, k: string, p: string} $envelope
 *
 * @return array<string, mixed>
 */
function adminOnFirebaseOpen(array $envelope): array
{
    $contentKey = '';
    openssl_private_decrypt(
        (string) base64_decode($envelope['k'], true),
        $contentKey,
        RecordingDelivery::privateKey(),
        OPENSSL_PKCS1_OAEP_PADDING,
    );

    $sealed = (string) base64_decode($envelope['p'], true);
    $plain = openssl_decrypt(substr($sealed, 28), 'aes-256-gcm', $contentKey, OPENSSL_RAW_DATA, substr($sealed, 0, 12), substr($sealed, 12, 16));

    return (array) json_decode((string) gzdecode((string) $plain), true);
}
