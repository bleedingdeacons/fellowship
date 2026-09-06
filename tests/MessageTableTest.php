<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The message table, from the statements outwards.
 *
 * <p>This was CredentialAndMessageTableTest. The credential half went
 * with its subject: the store is Unity's now, and so are the tests for
 * it, because Reach was testing the same statements against an identical
 * copy of the same class.</p>
 *
 * @covers \Fellowship\Messaging\WpdbMessageRepository
 */
final class MessageTableTest extends TestCase
{
    private RecordingWpdb $wpdb;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = new RecordingWpdb();
    }

    public function testAMessageInsertThatFailsThrows(): void
    {
        // The same reasoning as the device table: a Message with id 0
        // would be handed back, recipients written against it, and
        // nothing anywhere would say the message does not exist.
        $this->wpdb->insertResult = false;

        $this->expectException(\RuntimeException::class);

        $this->messages()->create(
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
            0,
        );
    }

    public function testSeveralMessagesAreFetchedInOneQuery(): void
    {
        // The inbox resolves a page of recipient rows to their messages.
        // One query per message would be a round trip per message.
        $this->wpdb->results = [];

        $this->messages()->findByIds([4, 9, 12]);

        self::assertCount(1, $this->wpdb->queries);
        self::assertStringContainsString('IN', $this->wpdb->lastQuery());
    }

    public function testAMessageIsDeletedById(): void
    {
        $this->wpdb->deleteResult = 1;

        self::assertTrue($this->messages()->delete(9));
        self::assertSame(['id' => 9], $this->wpdb->deletes[0]['where']);
    }

    public function testDeletingAMessageThatIsNotThereSaysSo(): void
    {
        $this->wpdb->deleteResult = 0;

        self::assertFalse($this->messages()->delete(9));
    }

    public function testAMessageIsReadBackFromItsRow(): void
    {
        $this->wpdb->results = [[
            'id' => 9,
            'uuid' => 'uuid-1',
            'sender_email' => 'dave@example.org',
            'sender_member_id' => 7,
            'sender_name' => 'Dave B',
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'audience_type' => 'committee',
            'audience_ref' => 'steering',
            'created_at' => 1788000000,
            'reply_to_id' => 0,
            'sender_device_id' => 4,
        ]];

        $message = $this->messages()->findById(9);

        self::assertNotNull($message);
        self::assertSame('Intergroup moved', $message->subject);
        self::assertSame('steering', $message->audienceRef);
        self::assertSame(4, $message->senderDeviceId);
    }

    private function messages(): WpdbMessageRepository
    {
        return new WpdbMessageRepository($this->wpdb);
    }
}
