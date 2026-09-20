<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Messaging\WpdbRecipientRepository;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The recipient table's writes and counts.
 *
 * <b>Delivery is recorded per member, so this table is the personal data
 * in the messaging half</b> — a row says that a named person was sent a
 * particular message. Two consequences are asserted here: the sweep can
 * find rows by the age of the message they belong to (recipients carry no
 * date of their own), and a member's rows can be removed on their own
 * when the member is deleted.
 *
 * The insert is INSERT IGNORE rather than check-then-insert, and that is
 * a concurrency decision rather than a style one: two sends racing on the
 * same committee would both see "not there" and both write. The unique
 * key is the arbiter, and letting it be one costs a duplicate-key warning
 * instead of a duplicate row — and a duplicate row here is a member
 * receiving the same message twice.
 */
#[CoversClass(\Fellowship\Messaging\WpdbRecipientRepository::class)]
final class RecipientTableTest extends TestCase
{
    private RecordingWpdb $wpdb;
    private WpdbRecipientRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = new RecordingWpdb();
        $this->repository = new WpdbRecipientRepository($this->wpdb);
    }

    public function testEachRecipientIsWrittenOnce(): void
    {
        $this->wpdb->queryResult = 1;

        $written = $this->repository->addMany(9, [
            ['email' => 'dave@example.org', 'member_id' => 7],
            ['email' => 'sue@example.org', 'member_id' => 8],
        ], 1788000000);

        self::assertSame(2, $written);
        self::assertCount(2, $this->wpdb->queries);
    }

    public function testTheInsertLetsTheUniqueKeyArbitrate(): void
    {
        // Two sends racing on the same committee would both see "not
        // there" on a check-then-insert, and both write.
        $this->wpdb->queryResult = 1;

        $this->repository->addMany(9, [['email' => 'dave@example.org', 'member_id' => 7]], 1788000000);

        self::assertStringContainsString('INSERT IGNORE', $this->wpdb->lastQuery());
    }

    public function testARowTheKeyRefusedIsNotCounted(): void
    {
        // Zero rows affected means the member already had this message.
        $this->wpdb->queryResult = 0;

        self::assertSame(0, $this->repository->addMany(
            9,
            [['email' => 'dave@example.org', 'member_id' => 7]],
            1788000000,
        ));
    }

    public function testAnEmptyAddressIsSkippedWithoutAQuery(): void
    {
        // A recipient row with no address is one nothing can ever be
        // delivered against.
        self::assertSame(0, $this->repository->addMany(9, [['email' => '', 'member_id' => 7]], 1788000000));
        self::assertSame([], $this->wpdb->queries);
    }

    public function testAddressesAreLoweredOnTheWayIn(): void
    {
        // Every read matches on a lowered address, so a mixed-case write
        // would be a row its own member could never see.
        $this->wpdb->queryResult = 1;

        $this->repository->addMany(9, [['email' => 'Dave@Example.ORG', 'member_id' => 7]], 1788000000);

        self::assertStringContainsString('dave@example.org', $this->wpdb->lastQuery());
    }

    public function testMarkingPushedIsScopedToOneMembersRow(): void
    {
        $this->repository->markPushed(9, 'dave@example.org', 1788000100);

        self::assertSame(
            ['message_id' => 9, 'member_email' => 'dave@example.org'],
            $this->wpdb->updates[0]['where'],
        );
    }

    public function testMarkingReceivedIsScopedToTheMembersOwnRows(): void
    {
        $this->wpdb->queryResult = 2;

        self::assertSame(2, $this->repository->markReceived([9, 10], 'Dave@Example.org', 1788000100));

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('dave@example.org', $sql);
        self::assertStringContainsString('message_id IN (9,10)', $sql);
    }

    public function testMarkingReceivedKeepsTheFirstTime(): void
    {
        // A tablet catching up a week later is not when the message arrived.
        $this->repository->markReceived([9], 'dave@example.org', 1788000100);

        self::assertStringContainsString('received_at IS NULL', $this->wpdb->lastQuery());
    }

    public function testMarkingNothingReceivedRunsNoQuery(): void
    {
        self::assertSame(0, $this->repository->markReceived([0, -3], 'dave@example.org', 1788000100));
        self::assertSame([], $this->wpdb->queries);
    }

    public function testReadingMarksReceivedWhereItWasNot(): void
    {
        $this->wpdb->queryResult = 1;

        $this->repository->markRead(9, 'dave@example.org', 1788000100);

        self::assertStringContainsString('received_at = COALESCE(received_at, 1788000100)', $this->wpdb->lastQuery());
    }

    public function testReceiptsAreCountedInOneGroupedQuery(): void
    {
        $this->wpdb->results = [
            ['message_id' => '9', 'recipients' => '5', 'received' => '3', 'read_count' => '2'],
        ];

        self::assertSame(
            [9 => ['recipients' => 5, 'received' => 3, 'read' => 2]],
            $this->repository->receiptsFor([9, 9]),
        );

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('GROUP BY message_id', $sql);
        self::assertStringContainsString('message_id IN (9)', $sql);
        // A read is a receipt, even when the acknowledgement was lost.
        self::assertStringContainsString('received_at IS NOT NULL OR read_at IS NOT NULL', $sql);
    }

    public function testAskingForNoReceiptsRunsNoQuery(): void
    {
        self::assertSame([], $this->repository->receiptsFor([]));
        self::assertSame([], $this->wpdb->queries);
    }

    public function testTheRecipientsOfAMessageAreListedInOrder(): void
    {
        $this->wpdb->results = [];

        $this->repository->forMessage(9);

        self::assertStringContainsString('ORDER BY id ASC', $this->wpdb->lastQuery());
    }

    public function testRecipientsAreCountedForOneMessage(): void
    {
        $this->wpdb->var = 12;

        self::assertSame(12, $this->repository->countForMessage(9));
        self::assertStringContainsString('message_id = 9', $this->wpdb->lastQuery());
    }

    public function testReadsAreCountedSeparately(): void
    {
        // What the admin log shows as "3 of 12 read".
        $this->wpdb->var = 3;

        self::assertSame(3, $this->repository->countReadForMessage(9));
        self::assertStringContainsString('read_at IS NOT NULL', $this->wpdb->lastQuery());
    }

    public function testTheSweepFindsRowsByTheAgeOfTheirMessage(): void
    {
        // Recipient rows carry no date of their own, so the sweep has to
        // reach the message to know how old they are. That join is also
        // why the sweep must run recipients first: deleting the messages
        // would leave nothing to find them by.
        $this->wpdb->queryResult = 4;

        self::assertSame(4, $this->repository->purgeForMessagesBefore(1788000000));

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('DELETE', $sql);
        self::assertStringContainsString('fellowship_messages', $sql);
    }

    public function testAMessagesRecipientsCanBeRemovedOnTheirOwn(): void
    {
        $this->wpdb->deleteResult = 3;

        self::assertSame(3, $this->repository->deleteForMessage(9));
        self::assertSame(['message_id' => 9], $this->wpdb->deletes[0]['where']);
    }

    public function testTheTableNameCarriesThePrefix(): void
    {
        self::assertStringEndsWith('fellowship_recipients', WpdbRecipientRepository::tableName($this->wpdb));
    }
}
