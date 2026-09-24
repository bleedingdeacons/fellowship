<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Tests\Support\RecordingWpdb;

/**
 * The message table, from the statements outwards.
 *
 * <p>This was CredentialAndMessageTableTest. The credential half went
 * with its subject: the store is Unity's now, and so are the tests for
 * it, because Reach was testing the same statements against an identical
 * copy of the same class.</p>
 */

covers(\Fellowship\Messaging\WpdbMessageRepository::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
});

test('a message insert that fails throws', function () {
    // The same reasoning as the device table: a Message with id 0
    // would be handed back, recipients written against it, and
    // nothing anywhere would say the message does not exist.
    $this->wpdb->insertResult = false;

    messageTableMessages()->create(
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
})->throws(\RuntimeException::class);

test('several messages are fetched in one query', function () {
    // The inbox resolves a page of recipient rows to their messages.
    // One query per message would be a round trip per message.
    $this->wpdb->results = [];

    messageTableMessages()->findByIds([4, 9, 12]);

    expect($this->wpdb->queries)->toHaveCount(1);
    expect($this->wpdb->lastQuery())->toContain('IN');
});

test('a message is deleted by id', function () {
    $this->wpdb->deleteResult = 1;

    expect(messageTableMessages()->delete(9))->toBeTrue();
    expect($this->wpdb->deletes[0]['where'])->toBe(['id' => 9]);
});

test('deleting a message that is not there says so', function () {
    $this->wpdb->deleteResult = 0;

    expect(messageTableMessages()->delete(9))->toBeFalse();
});

test('a message is read back from its row', function () {
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

    $message = messageTableMessages()->findById(9);

    expect($message)->not->toBeNull();
    expect($message->subject)->toBe('Intergroup moved');
    expect($message->audienceRef)->toBe('steering');
    expect($message->senderDeviceId)->toBe(4);
});

function messageTableMessages(): WpdbMessageRepository
{
    return new WpdbMessageRepository(test()->wpdb);
}
