<?php

declare(strict_types=1);

namespace Fellowship\Tests;

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

covers(\Fellowship\Messaging\WpdbRecipientRepository::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
    $this->repository = new WpdbRecipientRepository($this->wpdb);
});

test('each recipient is written once', function () {
    $this->wpdb->queryResult = 1;

    $written = $this->repository->addMany(9, [
        ['email' => 'dave@example.org', 'member_id' => 7],
        ['email' => 'sue@example.org', 'member_id' => 8],
    ], 1788000000);

    expect($written)->toBe(2);
    expect($this->wpdb->queries)->toHaveCount(2);
});

test('the insert lets the unique key arbitrate', function () {
    // Two sends racing on the same committee would both see "not
    // there" on a check-then-insert, and both write.
    $this->wpdb->queryResult = 1;

    $this->repository->addMany(9, [['email' => 'dave@example.org', 'member_id' => 7]], 1788000000);

    expect($this->wpdb->lastQuery())->toContain('INSERT IGNORE');
});

test('a row the key refused is not counted', function () {
    // Zero rows affected means the member already had this message.
    $this->wpdb->queryResult = 0;

    expect($this->repository->addMany(
        9,
        [['email' => 'dave@example.org', 'member_id' => 7]],
        1788000000,
    ))->toBe(0);
});

test('an empty address is skipped without a query', function () {
    // A recipient row with no address is one nothing can ever be
    // delivered against.
    expect($this->repository->addMany(9, [['email' => '', 'member_id' => 7]], 1788000000))->toBe(0);
    expect($this->wpdb->queries)->toBe([]);
});

test('addresses are lowered on the way in', function () {
    // Every read matches on a lowered address, so a mixed-case write
    // would be a row its own member could never see.
    $this->wpdb->queryResult = 1;

    $this->repository->addMany(9, [['email' => 'Dave@Example.ORG', 'member_id' => 7]], 1788000000);

    expect($this->wpdb->lastQuery())->toContain('dave@example.org');
});

test('marking pushed is scoped to one members row', function () {
    $this->repository->markPushed(9, 'dave@example.org', 1788000100);

    expect($this->wpdb->updates[0]['where'])->toBe(['message_id' => 9, 'member_email' => 'dave@example.org']);
});

test('marking received is scoped to the members own rows', function () {
    $this->wpdb->queryResult = 2;

    expect($this->repository->markReceived([9, 10], 'Dave@Example.org', 1788000100))->toBe(2);

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('dave@example.org');
    expect($sql)->toContain('message_id IN (9,10)');
});

test('marking received keeps the first time', function () {
    // A tablet catching up a week later is not when the message arrived.
    $this->repository->markReceived([9], 'dave@example.org', 1788000100);

    expect($this->wpdb->lastQuery())->toContain('received_at IS NULL');
});

test('marking nothing received runs no query', function () {
    expect($this->repository->markReceived([0, -3], 'dave@example.org', 1788000100))->toBe(0);
    expect($this->wpdb->queries)->toBe([]);
});

test('reading marks received where it was not', function () {
    $this->wpdb->queryResult = 1;

    $this->repository->markRead(9, 'dave@example.org', 1788000100);

    expect($this->wpdb->lastQuery())->toContain('received_at = COALESCE(received_at, 1788000100)');
});

test('receipts are counted in one grouped query', function () {
    $this->wpdb->results = [
        ['message_id' => '9', 'recipients' => '5', 'received' => '3', 'read_count' => '2'],
    ];

    expect($this->repository->receiptsFor([9, 9]))->toBe([9 => ['recipients' => 5, 'received' => 3, 'read' => 2]]);

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('GROUP BY message_id');
    expect($sql)->toContain('message_id IN (9)');
    // A read is a receipt, even when the acknowledgement was lost.
    expect($sql)->toContain('received_at IS NOT NULL OR read_at IS NOT NULL');
});

test('asking for no receipts runs no query', function () {
    expect($this->repository->receiptsFor([]))->toBe([]);
    expect($this->wpdb->queries)->toBe([]);
});

test('the recipients of a message are listed in order', function () {
    $this->wpdb->results = [];

    $this->repository->forMessage(9);

    expect($this->wpdb->lastQuery())->toContain('ORDER BY id ASC');
});

test('recipients are counted for one message', function () {
    $this->wpdb->var = 12;

    expect($this->repository->countForMessage(9))->toBe(12);
    expect($this->wpdb->lastQuery())->toContain('message_id = 9');
});

test('reads are counted separately', function () {
    // What the admin log shows as "3 of 12 read".
    $this->wpdb->var = 3;

    expect($this->repository->countReadForMessage(9))->toBe(3);
    expect($this->wpdb->lastQuery())->toContain('read_at IS NOT NULL');
});

test('the sweep finds rows by the age of their message', function () {
    // Recipient rows carry no date of their own, so the sweep has to
    // reach the message to know how old they are. That join is also
    // why the sweep must run recipients first: deleting the messages
    // would leave nothing to find them by.
    $this->wpdb->queryResult = 4;

    expect($this->repository->purgeForMessagesBefore(1788000000))->toBe(4);

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('DELETE');
    expect($sql)->toContain('fellowship_messages');
});

test('a messages recipients can be removed on their own', function () {
    $this->wpdb->deleteResult = 3;

    expect($this->repository->deleteForMessage(9))->toBe(3);
    expect($this->wpdb->deletes[0]['where'])->toBe(['message_id' => 9]);
});

test('the table name carries the prefix', function () {
    expect(WpdbRecipientRepository::tableName($this->wpdb))->toEndWith('fellowship_recipients');
});
