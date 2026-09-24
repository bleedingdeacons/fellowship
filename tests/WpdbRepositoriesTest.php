<?php

declare(strict_types=1);

namespace Fellowship\Tests;

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
 */

covers(\Fellowship\Messaging\WpdbMessageRepository::class, \Fellowship\Messaging\WpdbRecipientRepository::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
});

// ── Messages ──────────────────────────────────────────────────────

test('a message is written with its sender and body', function () {
    $this->wpdb->insert_id = 9;

    $message = wpdbRepositoriesMessages()->create(
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

    expect($message->id)->toBe(9);

    $written = $this->wpdb->inserts[0]['data'];
    expect($written['subject'])->toBe('Intergroup moved');
    expect($written['body'])->toBe('Now the 14th.');
});

test('messages are fetched newest first', function () {
    // The admin log and the app both read most-recent-first; an
    // ascending list would put the oldest message at the top of a
    // screen nobody scrolls to the bottom of.
    $this->wpdb->results = [];

    wpdbRepositoriesMessages()->list(25, 0);

    expect($this->wpdb->lastQuery())->toContain('ORDER BY id DESC');
});

test('asking for no messages at all answers nothing without a query', function () {
    // An empty IN () is a SQL syntax error, so this has to be caught
    // before the statement is built rather than after.
    expect(wpdbRepositoriesMessages()->findByIds([]))->toBe([]);
    expect($this->wpdb->queries)->toBe([]);
});

test('the retention sweep deletes by age', function () {
    // The retention window is a real control rather than
    // housekeeping: message bodies are stored in plain text and the
    // server can read them, so how long they are kept is the limit on
    // what a dump would contain.
    $this->wpdb->queryResult = 4;

    expect(wpdbRepositoriesMessages()->purgeBefore(1788000000))->toBe(4);
    expect($this->wpdb->lastQuery())->toContain('DELETE');
});

test('counting messages reads a single value', function () {
    $this->wpdb->var = 12;

    expect(wpdbRepositoriesMessages()->countAll())->toBe(12);
});

// ── Recipients ────────────────────────────────────────────────────

test('an inbox is paged from the highest id the handset holds', function () {
    $this->wpdb->results = [];

    wpdbRepositoriesRecipients()->forMember('member@example.org', 40, 50);

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('message_id > 40');
    expect($sql)->toContain('ORDER BY message_id DESC');
});

test('marking read is scoped to the members own row', function () {
    // The authorisation, and the only place it exists.
    $this->wpdb->queryResult = 1;

    expect(wpdbRepositoriesRecipients()->markRead(9, 'member@example.org', 1788000100))->toBeTrue();

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('member_email');
    expect($sql)->toContain('member@example.org');
});

test('marking somebody elses message read changes nothing', function () {
    // Zero rows affected, and reported as false — indistinguishable
    // from a message that does not exist, which is the point.
    $this->wpdb->queryResult = 0;

    expect(wpdbRepositoriesRecipients()->markRead(9, 'somebody@example.org', 1788000100))->toBeFalse();
});

test('unread is counted for one member only', function () {
    $this->wpdb->var = 3;

    expect(wpdbRepositoriesRecipients()->countUnread('member@example.org'))->toBe(3);

    $sql = $this->wpdb->lastQuery();
    expect($sql)->toContain('read_at IS NULL');
    expect($sql)->toContain('member@example.org');
});

test('adding no recipients writes nothing', function () {
    // A message addressed to a committee nobody is on. Building an
    // INSERT with no VALUES would be a syntax error.
    expect(wpdbRepositoriesRecipients()->addMany(9, [], 1788000000))->toBe(0);
    expect($this->wpdb->queries)->toBe([]);
});

test('deleting a members recipient rows is scoped to them', function () {
    // Used when a member is deleted. Scoping matters rather more here
    // than usual.
    $this->wpdb->deleteResult = 2;

    expect(wpdbRepositoriesRecipients()->deleteForMember('member@example.org'))->toBe(2);
    expect($this->wpdb->deletes[0]['where'])->toBe(['member_email' => 'member@example.org']);
});

// ── Credentials ───────────────────────────────────────────────────

/**
 * The credential table is not here any more: it is Unity's, and its
 * name is asserted in Unity's own suite.
 */
test('every table name carries the prefix', function () {
    expect(WpdbMessageRepository::tableName($this->wpdb))->toEndWith('fellowship_messages');
    expect(WpdbRecipientRepository::tableName($this->wpdb))->toEndWith('fellowship_recipients');
});

// ── Fixtures ──────────────────────────────────────────────────────

function wpdbRepositoriesMessages(): WpdbMessageRepository
{
    return new WpdbMessageRepository(test()->wpdb);
}

function wpdbRepositoriesRecipients(): WpdbRecipientRepository
{
    return new WpdbRecipientRepository(test()->wpdb);
}
