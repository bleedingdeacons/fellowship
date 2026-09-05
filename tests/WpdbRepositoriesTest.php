<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Messaging\WpdbRecipientRepository;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The message and recipient tables.
 *
 * <p>The credential table was here too, until it became Unity's. Its
 * tests went with it, and are not restated here: Reach was asserting the
 * same statements against an identical copy of the same class, and one
 * of the two would eventually have drifted.</p>
 *
 * <b>What is asserted is mostly the WHERE clause</b>, because in these
 * the WHERE clause *is* the security control and there is nowhere else
 * it can be checked. A handset marks a message read by naming it, and
 * the statement carries the member's own address. That is the
 * authorisation — a request naming somebody else's message affects
 * nothing and answers exactly as one naming a message that does not
 * exist. Move that condition into a caller and any handset can mark any
 * message read.
 *
 * @covers \Fellowship\Messaging\WpdbMessageRepository
 * @covers \Fellowship\Messaging\WpdbRecipientRepository
 */
final class WpdbRepositoriesTest extends TestCase
{
    private RecordingWpdb $wpdb;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = new RecordingWpdb();
    }

    // ── Messages ──────────────────────────────────────────────────────

    public function testAMessageIsWrittenWithItsSenderAndBody(): void
    {
        $this->wpdb->insert_id = 9;

        $message = $this->messages()->create(
            'uuid-1',
            'dave@example.org',
            7,
            'Dave B',
            'Intergroup moved',
            'Now the 14th.',
            'committee',
            'steering',
            1788000000,
            0,
            4,
        );

        self::assertSame(9, $message->id);

        $written = $this->wpdb->inserts[0]['data'];
        self::assertSame('Intergroup moved', $written['subject']);
        self::assertSame('Now the 14th.', $written['body']);
    }

    public function testMessagesAreFetchedNewestFirst(): void
    {
        // The admin log and the app both read most-recent-first; an
        // ascending list would put the oldest message at the top of a
        // screen nobody scrolls to the bottom of.
        $this->wpdb->results = [];

        $this->messages()->list(25, 0);

        self::assertStringContainsString('ORDER BY id DESC', $this->wpdb->lastQuery());
    }

    public function testAskingForNoMessagesAtAllAnswersNothingWithoutAQuery(): void
    {
        // An empty IN () is a SQL syntax error, so this has to be caught
        // before the statement is built rather than after.
        self::assertSame([], $this->messages()->findByIds([]));
        self::assertSame([], $this->wpdb->queries);
    }

    public function testTheRetentionSweepDeletesByAge(): void
    {
        // The retention window is a real control rather than
        // housekeeping: message bodies are stored in plain text and the
        // server can read them, so how long they are kept is the limit on
        // what a dump would contain.
        $this->wpdb->queryResult = 4;

        self::assertSame(4, $this->messages()->purgeBefore(1788000000));
        self::assertStringContainsString('DELETE', $this->wpdb->lastQuery());
    }

    public function testCountingMessagesReadsASingleValue(): void
    {
        $this->wpdb->var = 12;

        self::assertSame(12, $this->messages()->countAll());
    }

    // ── Recipients ────────────────────────────────────────────────────

    public function testAnInboxIsPagedFromTheHighestIdTheHandsetHolds(): void
    {
        $this->wpdb->results = [];

        $this->recipients()->forMember('member@example.org', 40, 50);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('message_id > 40', $sql);
        self::assertStringContainsString('ORDER BY message_id DESC', $sql);
    }

    public function testMarkingReadIsScopedToTheMembersOwnRow(): void
    {
        // The authorisation, and the only place it exists.
        $this->wpdb->queryResult = 1;

        self::assertTrue($this->recipients()->markRead(9, 'member@example.org', 1788000100));

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('member_email', $sql);
        self::assertStringContainsString('member@example.org', $sql);
    }

    public function testMarkingSomebodyElsesMessageReadChangesNothing(): void
    {
        // Zero rows affected, and reported as false — indistinguishable
        // from a message that does not exist, which is the point.
        $this->wpdb->queryResult = 0;

        self::assertFalse($this->recipients()->markRead(9, 'somebody@example.org', 1788000100));
    }

    public function testUnreadIsCountedForOneMemberOnly(): void
    {
        $this->wpdb->var = 3;

        self::assertSame(3, $this->recipients()->countUnread('member@example.org'));

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('read_at IS NULL', $sql);
        self::assertStringContainsString('member@example.org', $sql);
    }

    public function testAddingNoRecipientsWritesNothing(): void
    {
        // A message addressed to a committee nobody is on. Building an
        // INSERT with no VALUES would be a syntax error.
        self::assertSame(0, $this->recipients()->addMany(9, [], 1788000000));
        self::assertSame([], $this->wpdb->queries);
    }

    public function testDeletingAMembersRecipientRowsIsScopedToThem(): void
    {
        // Used when a member is deleted. Scoping matters rather more here
        // than usual.
        $this->wpdb->deleteResult = 2;

        self::assertSame(2, $this->recipients()->deleteForMember('member@example.org'));
        self::assertSame(
            ['member_email' => 'member@example.org'],
            $this->wpdb->deletes[0]['where'],
        );
    }

    // ── Credentials ───────────────────────────────────────────────────

    /**
     * The credential table is not here any more: it is Unity's, and its
     * name is asserted in Unity's own suite.
     */
    public function testEveryTableNameCarriesThePrefix(): void
    {
        self::assertStringEndsWith('fellowship_messages', WpdbMessageRepository::tableName($this->wpdb));
        self::assertStringEndsWith('fellowship_recipients', WpdbRecipientRepository::tableName($this->wpdb));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function messages(): WpdbMessageRepository
    {
        return new WpdbMessageRepository($this->wpdb);
    }

    private function recipients(): WpdbRecipientRepository
    {
        return new WpdbRecipientRepository($this->wpdb);
    }
}
