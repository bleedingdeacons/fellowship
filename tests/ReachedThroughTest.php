<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\MessagesPage;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDelivery;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Tests\Support\InMemoryMessageLog;
use Fellowship\Tests\Support\RecordingDelivery;
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
 * <b>The action form of the send API cannot report anything.</b>
 * `do_action` discards return values, so a message refused there is a
 * message that vanishes unless the refusal is logged — which is the only
 * thing separating "nobody sent one" from "one was thrown away".
 */

covers(\Fellowship\Messaging\MessageApi::class, \Fellowship\Directory\DirectoryPresenter::class, \Fellowship\Admin\MessagesPage::class);

beforeEach(function () {
    $_GET = [];
    WpState::$userCan = true;

    when('paginate_links')->justReturn('<a href="#">2</a>');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
    when('add_query_arg')->justReturn('https://example.org/wp-admin/admin.php');
    when('wp_generate_uuid4')->alias(static fn(): string => '11111111-2222-4333-8444-555555555555');

    $this->wpdb = new RecordingWpdb();
    $this->log = new InMemoryMessageLog();
    $this->delivery = new RecordingDelivery();
    $this->audit = new SpyAuditLogger();
});

// ── The send API ──────────────────────────────────────────────────

test('members can be named by directory id rather than by address', function () {
    // How the admin compose screen names one, and how a handset does.
    $id = reachedThroughApi()->send([
        'subject'    => 'Your rota',
        'body'       => 'Can you take Tuesday?',
        'member_ids' => [7],
    ]);

    expect($id)->toBeInt();
    expect(test()->delivery->resolved[0]['memberIds'])->toBe([7]);
    expect(test()->audit->entries[0]['detail'])->toContain('audience:' . Message::AUDIENCE_MEMBERS);
});

test('ids that name nobody are refused rather than sent to everyone', function () {
    // Dropped, they would leave a request naming nobody — the broadcast.
    $result = reachedThroughApi()->send([
        'subject'    => 'Your rota',
        'body'       => 'Can you take Tuesday?',
        'member_ids' => [99],
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_no_recipients');
    expect(test()->delivery->resolved)->toBe([]);
});

test('ids and a string of addresses together reach each member once', function () {
    $id = reachedThroughApi()->send([
        'subject'       => 'Your rota',
        'body'          => 'Can you take Tuesday?',
        'member_ids'    => [7],
        'member_emails' => 'dave@example.org, nobody@example.org',
    ]);

    expect($id)->toBeInt();
    expect(test()->delivery->resolved[0]['memberIds'])->toBe([7]);
});

test('a message sent through the API is sent and audited', function () {
    $id = reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect($id)->toBeInt();
    expect(test()->audit->entries)->not->toBeEmpty();
});

test('a send with no member behind it is attributed to nobody', function () {
    // Entity id 0 is the intergroup speaking. Inventing a member to
    // attribute it to would make the audit trail say something
    // untrue.
    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect(test()->audit->entries[0]['entityId'])->toBe(0);
});

test('a send with no sender name is signed with the site name', function () {
    when('get_bloginfo')->justReturn('Bristol Intergroup');

    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect(reachedThroughSentSender())->toBe('Bristol Intergroup');
});

test('a site with no name is still signed with something', function () {
    // A blank "from" on a handset reads as a message from nobody.
    when('get_bloginfo')->justReturn('');

    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
    ]);

    expect(reachedThroughSentSender())->toBe('Intergroup');
});

test('a caller can sign the message itself', function () {
    reachedThroughApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['dave@example.org'],
        'sender_name' => 'The Steering Committee',
    ]);

    expect(reachedThroughSentSender())->toBe('The Steering Committee');
});

test('a malformed request is refused rather than sent', function () {
    $result = reachedThroughApi()->send(['subject' => '', 'body' => '']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect(test()->delivery->resolved)->toBe([]);
});

test('a fault while sending is an error rather than a fatal', function () {
    // It must not propagate into whatever plugin asked to send.
    $members = reachedThroughMembers();

    $api = new MessageApi(
        new class implements MessageDelivery {
            public function resolve(array $audience): array
            {
                throw new RuntimeException('Something broke.');
            }

            public function deliver(array $audience, int $id, array $envelopes): int
            {
                return 0;
            }
        },
        new MessageSealer(),
        new RecipientResolver($members, new InMemoryCommitteeRepository(), new MemberGate($members)),
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

    expect(test()->delivery->delivered)->toHaveCount(1);
});

test('the action form logs a refusal rather than dropping it silently', function () {
    // do_action discards return values, so a refusal that is not
    // logged is a message that simply vanished.
    reachedThroughApi()->sendFromAction(['subject' => '', 'body' => '']);

    expect(test()->delivery->delivered)->toBe([]);
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
    );

    expect($directory->forApp(false)['members'])->toBe([]);
});

// ── The log's own rendering ───────────────────────────────────────

test('the log paginates once there is more than one page', function () {
    for ($i = 0; $i < 60; $i++) {
        test()->log->add();
    }

    expect(renderLog())->toContain('tablenav-pages');
});

test('the last page has no next page', function () {
    for ($i = 0; $i < 25; $i++) {
        test()->log->add();
    }

    expect(renderLog())->not->toContain('tablenav-pages');
});

test('a message with no date shows nothing rather than the epoch', function () {
    // "1 Jan 1970" in the sent column reads as a bug in the data
    // rather than as an absent date.
    test()->log->add(createdAt: 0);

    expect(renderLog())->not->toContain('1970');
});

// ── Fixtures ──────────────────────────────────────────────────────

/** The name a sent message was sealed under, opened as a handset would. */
function reachedThroughSentSender(): string
{
    $envelope = test()->delivery->delivered[0]['envelopes'][0];
    $contentKey = '';
    openssl_private_decrypt((string) base64_decode($envelope['k'], true), $contentKey, RecordingDelivery::privateKey(), OPENSSL_PKCS1_OAEP_PADDING);
    $sealed = (string) base64_decode($envelope['p'], true);
    $plain = openssl_decrypt(substr($sealed, 28), 'aes-256-gcm', $contentKey, OPENSSL_RAW_DATA, substr($sealed, 0, 12), substr($sealed, 12, 16));

    return (string) (json_decode((string) gzdecode((string) $plain), true)['sender'] ?? '');
}

function renderLog(): string
{
    return captureOutput(fn() => (new MessagesPage(test()->log, reachedThroughMembers()))->render());
}

function reachedThroughApi(): MessageApi
{
    $members = reachedThroughMembers();

    return new MessageApi(
        test()->delivery,
        new MessageSealer(),
        new RecipientResolver($members, new InMemoryCommitteeRepository(), new MemberGate($members)),
        test()->audit,
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
    );
}
