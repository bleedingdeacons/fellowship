<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\MessagesPage;
use Fellowship\Devices\MemberGate;
use Fellowship\Devices\WpdbDeviceRepository;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Messaging\WpdbRecipientRepository;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Fellowship\Tests\Support\RecordingWpdb;
use RuntimeException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;

/**
 * Paths every other test walks through without looking at.
 *
 * <b>Reading a row back is not the same as writing one.</b> The
 * repository tests assert on the SQL, because that is where the
 * behaviour lives — `revoked_at IS NULL` is part of the lookup rather
 * than a check a caller makes afterwards. What that leaves untouched is
 * the other half: turning a database row into an object. Hydration is
 * where a renamed column or an integer arriving as a string becomes a
 * fatal, and none of it is visible from a statement.
 *
 * <b>The action form of the send API cannot report anything.</b>
 * `do_action` discards return values, so a message refused there is a
 * message that vanishes unless the refusal is logged — which is the only
 * thing separating "nobody sent one" from "one was thrown away".
 */

covers(\Fellowship\Messaging\MessageApi::class, \Fellowship\Directory\DirectoryPresenter::class, \Fellowship\Messaging\WpdbRecipientRepository::class, \Fellowship\Messaging\WpdbMessageRepository::class, \Fellowship\Devices\WpdbDeviceRepository::class, \Fellowship\Admin\MessagesPage::class);

beforeEach(function () {
    $_GET = [];
    WpState::$userCan = true;

    when('paginate_links')->justReturn('<a href="#">2</a>');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
    when('add_query_arg')->justReturn('https://example.org/wp-admin/admin.php');
    when('wp_generate_uuid4')->alias(static fn(): string => '11111111-2222-4333-8444-555555555555');

    $this->wpdb = new RecordingWpdb();
    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->devices = new InMemoryDeviceRepository();
});

// ── The send API ──────────────────────────────────────────────────

test('a message sent through the API is stored and audited', function () {
    $audit = new SpyAuditLogger();

    $id = reachedThroughApi($audit)->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect($id)->toBeInt();
    expect($audit->entries)->not->toBeEmpty();
});

test('a send with no member behind it is attributed to nobody', function () {
    // Entity id 0 is the intergroup speaking. Inventing a member to
    // attribute it to would make the audit trail say something
    // untrue.
    $audit = new SpyAuditLogger();

    reachedThroughApi($audit)->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect($audit->entries)->not->toBeEmpty();
});

test('a send with no sender name is signed with the site name', function () {
    when('get_bloginfo')->justReturn('Bristol Intergroup');

    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect(reachedThroughStored()->senderName)->toBe('Bristol Intergroup');
});

test('a site with no name is still signed with something', function () {
    // A blank "from" on a handset reads as a message from nobody.
    when('get_bloginfo')->justReturn('');

    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect(reachedThroughStored()->senderName)->toBe('Intergroup');
});

test('a caller can sign the message itself', function () {
    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
        'sender_name' => 'The Steering Committee',
    ]);

    expect(reachedThroughStored()->senderName)->toBe('The Steering Committee');
});

test('a malformed request is refused rather than stored', function () {
    $result = reachedThroughApi()->send(['subject' => '', 'body' => '']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toBe([]);
});

test('a storage failure is an error rather than a fatal', function () {
    // It must not propagate into whatever plugin asked to send.
    $members = reachedThroughMembers();
    $gate = new MemberGate($members);

    $api = new MessageApi(
        new MessageDispatcher(reachedThroughThrowingMessages(), $this->recipients, $this->devices, reachedThroughTransport()),
        new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
        new SpyAuditLogger(),
    );

    $result = $api->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_send_failed');
});

test('the action form sends without answering anything', function () {
    reachedThroughApi()->sendFromAction([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect($this->messages->rows)->toHaveCount(1);
});

test('the action form logs a refusal rather than dropping it silently', function () {
    // do_action discards return values, so a refusal that is not
    // logged is a message that simply vanished.
    reachedThroughApi()->sendFromAction(['subject' => '', 'body' => '']);

    expect($this->messages->rows)->toBe([]);
});

// ── The address book ──────────────────────────────────────────────

test('committees are listed when the app asks for them', function () {
    $directory = reachedThroughPresenter([
        new CommitteeStub(id: 2, slug: 'steering', name: 'Steering', parentId: 0),
        new CommitteeStub(id: 3, slug: 'archives', name: 'Archives', parentId: 2),
    ]);

    $committees = $directory->forApp(true)['committees'];

    expect($committees)->toHaveCount(2);
    expect($committees[0])->toBe(['slug' => 'archives', 'name' => 'Archives', 'parent' => 2]);
});

test('committees are omitted when the app does not ask for them', function () {
    $directory = reachedThroughPresenter([new CommitteeStub(id: 2, slug: 'steering', name: 'Steering')]);

    expect($directory->forApp(false)['committees'])->toBe([]);
});

test('committees are ordered by name rather than by term id', function () {
    // The app renders the list as it arrives, so the ordering is a
    // server-side decision or it is nobody's.
    $directory = reachedThroughPresenter([
        new CommitteeStub(id: 9, slug: 'steering', name: 'Steering'),
        new CommitteeStub(id: 2, slug: 'archives', name: 'Archives'),
    ]);

    $names = array_column($directory->forApp(true)['committees'], 'name');

    expect($names)->toBe(['Archives', 'Steering']);
});

test('a member the gate refuses is not in the address book', function () {
    // Being listed and being reachable are the same permission here:
    // the app can only address somebody it can see.
    $members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: ''),
    ]);

    $directory = new DirectoryPresenter(
        $members,
        new InMemoryCommitteeRepository(),
        new MemberGate($members),
        $this->devices,
    );

    expect($directory->forApp(false)['members'])->toBe([]);
});

// ── Reading rows back ─────────────────────────────────────────────

test('recipient rows become recipients', function () {
    $this->wpdb->results = [
        [
            'id' => 1,
            'message_id' => 9,
            'member_email' => 'dave@example.org',
            'member_id' => 7,
            'created_at' => 1788000000,
            'read_at' => 1788000100,
            'pushed_at' => null,
        ],
    ];

    $recipients = (new WpdbRecipientRepository($this->wpdb))->forMessage(9);

    expect($recipients)->toHaveCount(1);
    expect($recipients[0]->memberEmail)->toBe('dave@example.org');
    expect($recipients[0]->readAt)->toBe(1788000100);
});

test('a recipient nobody has read carries no read date', function () {
    // Null rather than zero: the log counts reads by asking whether
    // the column is set, and a zero would read as "read in 1970".
    $this->wpdb->results = [
        [
            'id' => 1,
            'message_id' => 9,
            'member_email' => 'dave@example.org',
            'member_id' => 7,
            'created_at' => 1788000000,
        ],
    ];

    $recipients = (new WpdbRecipientRepository($this->wpdb))->forMessage(9);

    expect($recipients[0]->readAt)->toBeNull();
    expect($recipients[0]->pushedAt)->toBeNull();
});

test('message rows become messages', function () {
    $this->wpdb->results = [messageRow(9), messageRow(10)];

    $messages = (new WpdbMessageRepository($this->wpdb))->list(20, 0);

    expect($messages)->toHaveCount(2);
    expect($messages[0]->subject)->toBe('Intergroup moved');
});

test('messages fetched together are keyed by their id', function () {
    // The log reads them back in one query and then looks each one
    // up by id, so a plain list would make the screen O(n^2).
    $this->wpdb->results = [messageRow(9), messageRow(10)];

    $messages = (new WpdbMessageRepository($this->wpdb))->findByIds([9, 10]);

    expect($messages)->toHaveKey(9);
    expect($messages[10]->id)->toBe(10);
});

test('a key fault is cleared when a handset rotates its key', function () {
    // Left set, the admin list would keep flagging a handset that is
    // now perfectly healthy.
    (new WpdbDeviceRepository($this->wpdb))->clearKeyFault(4);

    expect($this->wpdb->updates[0]['data'])->toBe(['key_fault_at' => null]);
    expect($this->wpdb->updates[0]['where'])->toBe(['id' => 4]);
});

// ── The log's own rendering ───────────────────────────────────────

test('a long body is shortened rather than breaking the column', function () {
    reachedThroughStore('Intergroup moved', str_repeat('a very long sentence indeed ', 20), 1788000000);

    expect(renderLog())->toContain('…');
});

test('the log paginates once there is more than one page', function () {
    for ($i = 0; $i < 60; $i++) {
        reachedThroughStore('Subject ' . $i, 'Body', 1788000000);
    }

    expect(renderLog())->toContain('tablenav-pages');
});

test('a message with no date shows nothing rather than the epoch', function () {
    // "1 Jan 1970" in the sent column reads as a bug in the data
    // rather than as an absent date.
    reachedThroughStore('Intergroup moved', 'Now the 14th.', 0);

    expect(renderLog())->not->toContain('1970');
});

// ── Fixtures ──────────────────────────────────────────────────────

function reachedThroughStore(string $subject, string $body, int $createdAt): void
{
    test()->messages->create(
        'uuid-' . count(test()->messages->rows),
        'dave@example.org',
        7,
        'Dave P',
        $subject,
        $body,
        'all',
        '',
        $createdAt,
        0,
        0,
    );
}

function reachedThroughStored(): Message
{
    expect(test()->messages->rows)->not->toBe([], 'Nothing was stored.');

    return array_values(test()->messages->rows)[0];
}

function reachedThroughTransport(): FcmTransport
{
    return new FcmTransport(new FcmClient(), new Settings(), new MessageSealer());
}

function renderLog(): string
{
    return captureOutput(fn() => (new MessagesPage(test()->messages, test()->recipients))->render());
}

function reachedThroughApi(?SpyAuditLogger $audit = null): MessageApi
{
    $members = reachedThroughMembers();
    $gate = new MemberGate($members);

    return new MessageApi(
        new MessageDispatcher(test()->messages, test()->recipients, test()->devices, reachedThroughTransport()),
        new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
        $audit ?? new SpyAuditLogger(),
    );
}

function reachedThroughMembers(): InMemoryMemberRepository
{
    return new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: 'dave@example.org'),
    ]);
}

/** @param list<CommitteeStub> $committees */
function reachedThroughPresenter(array $committees): DirectoryPresenter
{
    $members = reachedThroughMembers();

    return new DirectoryPresenter(
        $members,
        new InMemoryCommitteeRepository($committees),
        new MemberGate($members),
        test()->devices,
    );
}

function reachedThroughThrowingMessages(): InMemoryMessageRepository
{
    return new class extends InMemoryMessageRepository {
        public function create(
            string $uuid,
            string $senderEmail,
            int $senderId,
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

/** @return array<string, mixed> */
function messageRow(int $id): array
{
    return [
        'id' => $id,
        'uuid' => 'uuid-' . $id,
        'sender_email' => 'dave@example.org',
        'sender_id' => 7,
        'sender_name' => 'Dave P',
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'audience_type' => 'all',
        'audience_ref' => '',
        'created_at' => 1788000000,
        'reply_to' => 0,
        'device_id' => 0,
    ];
}
