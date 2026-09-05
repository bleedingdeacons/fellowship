<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Auth\WpdbPasswordCredentialRepository;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The credential and message tables, from the statements outwards.
 *
 * <b>Every credential write is an upsert, and that is not a
 * convenience.</b> A member has no row until they ask for a password, so
 * the first reset and every later change go through the same path — a
 * check-then-insert would race two requests into two rows for one
 * address, and the second one would be a credential nobody can reach.
 *
 * <b>Setting a password clears the token and the lockout in the same
 * statement.</b> That is what makes the emailed code the recovery route
 * for somebody locked out by five wrong guesses; doing it in two writes
 * would leave a window where the new password is set and the account is
 * still locked.
 *
 * @covers \Fellowship\Auth\WpdbPasswordCredentialRepository
 * @covers \Fellowship\Messaging\WpdbMessageRepository
 */
final class CredentialAndMessageTableTest extends TestCase
{
    private RecordingWpdb $wpdb;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = new RecordingWpdb();
    }

    // ── Credentials ───────────────────────────────────────────────────

    public function testSettingAPasswordCreatesTheRowOrReplacesIt(): void
    {
        // The member had no row until they asked for a password.
        $this->credentials()->upsertPasswordHash('member@example.org', 'argon2-hash', 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('INSERT INTO', $sql);
        self::assertStringContainsString('ON DUPLICATE KEY UPDATE', $sql);
    }

    public function testSettingAPasswordClearsTheTokenAndLockoutInOneStatement(): void
    {
        // Two writes would leave a window where the new password works
        // and the account is still locked.
        $this->credentials()->upsertPasswordHash('member@example.org', 'argon2-hash', 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString("reset_token_hash = ''", $sql);
        self::assertStringContainsString('locked_until = 0', $sql);
        self::assertStringContainsString('failed_attempts = 0', $sql);
    }

    public function testStoringAResetTokenLeavesAnExistingPasswordAlone(): void
    {
        // Asking for a code must not lock somebody out of the password
        // they already have, in case they never use the code.
        $this->credentials()->storeResetToken('member@example.org', str_repeat('a', 64), 1788003600, 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('reset_token_hash = VALUES(reset_token_hash)', $sql);
        self::assertStringNotContainsString('password_hash = VALUES', $sql);
    }

    public function testClearingAResetTokenIsScopedToOneAddress(): void
    {
        $this->credentials()->clearResetToken('member@example.org', 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('UPDATE', $sql);
        self::assertStringContainsString('member@example.org', $sql);
    }

    public function testAFailedAttemptOnlyEverUpdates(): void
    {
        // Never an insert: an unknown address has no password to guess,
        // and seeding a row would let a lockout be induced for an account
        // that does not exist.
        $this->credentials()->recordFailedAttempt('nobody@example.org', 3, 0, 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringStartsWith('UPDATE', trim($sql));
        self::assertSame([], $this->wpdb->inserts);
    }

    public function testASuccessfulLoginZeroesTheCounters(): void
    {
        $this->credentials()->resetFailedAttempts('member@example.org', 1788000000);

        $sql = $this->wpdb->lastQuery();
        self::assertStringContainsString('failed_attempts', $sql);
        self::assertStringContainsString('locked_until', $sql);
    }

    public function testACredentialIsDeletedByAddress(): void
    {
        $this->credentials()->delete('member@example.org');

        self::assertSame(['email' => 'member@example.org'], $this->wpdb->deletes[0]['where']);
    }

    // ── Messages ──────────────────────────────────────────────────────

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

    private function credentials(): WpdbPasswordCredentialRepository
    {
        return new WpdbPasswordCredentialRepository($this->wpdb);
    }

    private function messages(): WpdbMessageRepository
    {
        return new WpdbMessageRepository($this->wpdb);
    }
}
