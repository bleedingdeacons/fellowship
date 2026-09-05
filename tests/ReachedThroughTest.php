<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\MessagesPage;
use Fellowship\Auth\WpdbPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Messaging\MessageApi
 * @covers \Fellowship\Directory\DirectoryPresenter
 * @covers \Fellowship\Messaging\WpdbRecipientRepository
 * @covers \Fellowship\Messaging\WpdbMessageRepository
 * @covers \Fellowship\Devices\WpdbDeviceRepository
 * @covers \Fellowship\Auth\WpdbPasswordCredentialRepository
 * @covers \Fellowship\Admin\MessagesPage
 */
final class ReachedThroughTest extends TestCase
{
    private RecordingWpdb $wpdb;
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryDeviceRepository $devices;

    protected function setUp(): void
    {
        parent::setUp();

        $_GET = [];
        WpState::$userCan = true;

        Functions\when('paginate_links')->justReturn('<a href="#">2</a>');
        Functions\when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
        Functions\when('add_query_arg')->justReturn('https://example.org/wp-admin/admin.php');
        Functions\when('wp_generate_uuid4')->alias(static fn(): string => '11111111-2222-4333-8444-555555555555');

        $this->wpdb = new RecordingWpdb();
        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->devices = new InMemoryDeviceRepository();
    }

    // ── The send API ──────────────────────────────────────────────────

    public function testAMessageSentThroughTheApiIsStoredAndAudited(): void
    {
        $audit = new SpyAuditLogger();

        $id = $this->api($audit)->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertIsInt($id);
        self::assertNotEmpty($audit->entries);
    }

    public function testASendWithNoMemberBehindItIsAttributedToNobody(): void
    {
        // Entity id 0 is the intergroup speaking. Inventing a member to
        // attribute it to would make the audit trail say something
        // untrue.
        $audit = new SpyAuditLogger();

        $this->api($audit)->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertNotEmpty($audit->entries);
    }

    public function testASendWithNoSenderNameIsSignedWithTheSiteName(): void
    {
        Functions\when('get_bloginfo')->justReturn('Bristol Intergroup');

        $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertSame('Bristol Intergroup', $this->stored()->senderName);
    }

    public function testASiteWithNoNameIsStillSignedWithSomething(): void
    {
        // A blank "from" on a handset reads as a message from nobody.
        Functions\when('get_bloginfo')->justReturn('');

        $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertSame('Intergroup', $this->stored()->senderName);
    }

    public function testACallerCanSignTheMessageItself(): void
    {
        $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
            'sender_name' => 'The Steering Committee',
        ]);

        self::assertSame('The Steering Committee', $this->stored()->senderName);
    }

    public function testAMalformedRequestIsRefusedRatherThanStored(): void
    {
        $result = $this->api()->send(['subject' => '', 'body' => '']);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame([], $this->messages->rows);
    }

    public function testAStorageFailureIsAnErrorRatherThanAFatal(): void
    {
        // It must not propagate into whatever plugin asked to send.
        $members = $this->members();
        $gate = new MemberGate($members);

        $api = new MessageApi(
            new MessageDispatcher($this->throwingMessages(), $this->recipients, $this->devices, $this->transport()),
            new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
            new SpyAuditLogger(),
        );

        $result = $api->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('fellowship_send_failed', $result->get_error_code());
    }

    public function testTheActionFormSendsWithoutAnsweringAnything(): void
    {
        $this->api()->sendFromAction([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['dave@example.org'],
        ]);

        self::assertCount(1, $this->messages->rows);
    }

    public function testTheActionFormLogsARefusalRatherThanDroppingItSilently(): void
    {
        // do_action discards return values, so a refusal that is not
        // logged is a message that simply vanished.
        $this->api()->sendFromAction(['subject' => '', 'body' => '']);

        self::assertSame([], $this->messages->rows);
    }

    // ── The address book ──────────────────────────────────────────────

    public function testCommitteesAreListedWhenTheAppAsksForThem(): void
    {
        $directory = $this->presenter([
            new CommitteeStub(id: 2, slug: 'steering', name: 'Steering', parentId: 0),
            new CommitteeStub(id: 3, slug: 'archives', name: 'Archives', parentId: 2),
        ]);

        $committees = $directory->forApp(true)['committees'];

        self::assertCount(2, $committees);
        self::assertSame(['slug' => 'archives', 'name' => 'Archives', 'parent' => 2], $committees[0]);
    }

    public function testCommitteesAreOmittedWhenTheAppDoesNotAskForThem(): void
    {
        $directory = $this->presenter([new CommitteeStub(id: 2, slug: 'steering', name: 'Steering')]);

        self::assertSame([], $directory->forApp(false)['committees']);
    }

    public function testCommitteesAreOrderedByNameRatherThanByTermId(): void
    {
        // The app renders the list as it arrives, so the ordering is a
        // server-side decision or it is nobody's.
        $directory = $this->presenter([
            new CommitteeStub(id: 9, slug: 'steering', name: 'Steering'),
            new CommitteeStub(id: 2, slug: 'archives', name: 'Archives'),
        ]);

        $names = array_column($directory->forApp(true)['committees'], 'name');

        self::assertSame(['Archives', 'Steering'], $names);
    }

    public function testAMemberTheGateRefusesIsNotInTheAddressBook(): void
    {
        // Being listed and being reachable are the same permission here:
        // the app can only address somebody it can see.
        $members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: ''),
        ]);

        $directory = new DirectoryPresenter($members, new InMemoryCommitteeRepository(), new MemberGate($members));

        self::assertSame([], $directory->forApp(false)['members']);
    }

    // ── Reading rows back ─────────────────────────────────────────────

    public function testRecipientRowsBecomeRecipients(): void
    {
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

        self::assertCount(1, $recipients);
        self::assertSame('dave@example.org', $recipients[0]->memberEmail);
        self::assertSame(1788000100, $recipients[0]->readAt);
    }

    public function testARecipientNobodyHasReadCarriesNoReadDate(): void
    {
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

        self::assertNull($recipients[0]->readAt);
        self::assertNull($recipients[0]->pushedAt);
    }

    public function testMessageRowsBecomeMessages(): void
    {
        $this->wpdb->results = [$this->messageRow(9), $this->messageRow(10)];

        $messages = (new WpdbMessageRepository($this->wpdb))->list(20, 0);

        self::assertCount(2, $messages);
        self::assertSame('Intergroup moved', $messages[0]->subject);
    }

    public function testMessagesFetchedTogetherAreKeyedByTheirId(): void
    {
        // The log reads them back in one query and then looks each one
        // up by id, so a plain list would make the screen O(n^2).
        $this->wpdb->results = [$this->messageRow(9), $this->messageRow(10)];

        $messages = (new WpdbMessageRepository($this->wpdb))->findByIds([9, 10]);

        self::assertArrayHasKey(9, $messages);
        self::assertSame(10, $messages[10]->id);
    }

    public function testAKeyFaultIsClearedWhenAHandsetRotatesItsKey(): void
    {
        // Left set, the admin list would keep flagging a handset that is
        // now perfectly healthy.
        (new WpdbDeviceRepository($this->wpdb))->clearKeyFault(4);

        self::assertSame(['key_fault_at' => null], $this->wpdb->updates[0]['data']);
        self::assertSame(['id' => 4], $this->wpdb->updates[0]['where']);
    }

    public function testACredentialIsFoundByItsResetToken(): void
    {
        $this->wpdb->results = [[
            'email' => 'dave@example.org',
            'password_hash' => '$argon2id$v=19$m=1,t=1,p=1$x$y',
            'reset_token_hash' => str_repeat('a', 64),
            'reset_expires_at' => 1788003600,
            'failed_attempts' => 0,
            'locked_until' => 0,
            'updated_at' => 1788000000,
        ]];

        $found = (new WpdbPasswordCredentialRepository($this->wpdb))->findByResetTokenHash(str_repeat('a', 64));

        self::assertNotNull($found);
        self::assertSame('dave@example.org', $found->email);
    }

    public function testABlankResetTokenResolvesToNothingWithoutAQuery(): void
    {
        // An empty hash would otherwise match every reset-free row.
        self::assertNull((new WpdbPasswordCredentialRepository($this->wpdb))->findByResetTokenHash(''));
        self::assertSame([], $this->wpdb->queries);
    }

    // ── The log's own rendering ───────────────────────────────────────

    public function testALongBodyIsShortenedRatherThanBreakingTheColumn(): void
    {
        $this->store('Intergroup moved', str_repeat('a very long sentence indeed ', 20), 1788000000);

        self::assertStringContainsString('…', $this->renderLog());
    }

    public function testTheLogPaginatesOnceThereIsMoreThanOnePage(): void
    {
        for ($i = 0; $i < 60; $i++) {
            $this->store('Subject ' . $i, 'Body', 1788000000);
        }

        self::assertStringContainsString('tablenav-pages', $this->renderLog());
    }

    public function testAMessageWithNoDateShowsNothingRatherThanTheEpoch(): void
    {
        // "1 Jan 1970" in the sent column reads as a bug in the data
        // rather than as an absent date.
        $this->store('Intergroup moved', 'Now the 14th.', 0);

        self::assertStringNotContainsString('1970', $this->renderLog());
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function store(string $subject, string $body, int $createdAt): void
    {
        $this->messages->create(
            'uuid-' . count($this->messages->rows),
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

    private function stored(): Message
    {
        self::assertNotSame([], $this->messages->rows, 'Nothing was stored.');

        return array_values($this->messages->rows)[0];
    }

    private function transport(): FcmTransport
    {
        return new FcmTransport(new FcmClient(), new Settings(), new MessageSealer());
    }

    private function renderLog(): string
    {
        ob_start();

        try {
            (new MessagesPage($this->messages, $this->recipients))->render();
        } finally {
            $markup = (string) ob_get_clean();
        }

        return $markup;
    }

    private function api(?SpyAuditLogger $audit = null): MessageApi
    {
        $members = $this->members();
        $gate = new MemberGate($members);

        return new MessageApi(
            new MessageDispatcher($this->messages, $this->recipients, $this->devices, $this->transport()),
            new RecipientResolver($members, new InMemoryCommitteeRepository(), $gate),
            $audit ?? new SpyAuditLogger(),
        );
    }

    private function members(): InMemoryMemberRepository
    {
        return new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: 'dave@example.org'),
        ]);
    }

    /** @param list<CommitteeStub> $committees */
    private function presenter(array $committees): DirectoryPresenter
    {
        $members = $this->members();

        return new DirectoryPresenter(
            $members,
            new InMemoryCommitteeRepository($committees),
            new MemberGate($members),
        );
    }

    private function throwingMessages(): InMemoryMessageRepository
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
    private function messageRow(int $id): array
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
}
