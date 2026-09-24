<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRequest;
use WP_Error;

/**
 * Validation, and the caps that keep a sealed payload inside FCM's limit.
 */

test('a committee audience is recognised', function () {
    $request = MessageRequest::fromArray([
        'subject'   => 'Meeting moved',
        'body'      => 'To the 14th.',
        'committee' => 'public-information',
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_COMMITTEE);
    expect($request->audienceRef)->toBe('public-information');
});

test('named members are recognised', function () {
    $request = MessageRequest::fromArray([
        'subject'       => 'Rota',
        'body'          => 'Can you cover Thursday?',
        'member_emails' => ['A@Example.org', 'b@example.org'],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_MEMBERS);
    expect($request->memberEmails)->toBe(['a@example.org', 'b@example.org']);
});

test('no audience means everyone', function () {
    $request = MessageRequest::fromArray(['subject' => 'Notice', 'body' => 'Read this.']);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_ALL);
});

test('a committee and named members together are allowed', function () {
    // This was refused until 2026-09-11, on the grounds that the
    // recipient list could not be explained back to the sender. It
    // can: the list is stored per member in the recipients table
    // whatever the audience, and the workaround people used instead
    // was to send twice — which is worse for anyone in both.
    $request = MessageRequest::fromArray([
        'subject'       => 'Both',
        'body'          => 'At once.',
        'committees'    => ['literature'],
        'member_emails' => ['a@example.org'],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_MIXED);
    expect($request->committees)->toBe(['literature']);
    expect($request->memberEmails)->toBe(['a@example.org']);
});

test('several committees travel together', function () {
    $request = MessageRequest::fromArray([
        'subject'    => 'Two committees',
        'body'       => 'At once.',
        'committees' => ['literature', 'public-information'],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_COMMITTEE);
    expect($request->committees)->toBe(['literature', 'public-information']);

    // Joined for storage, because that is the shape of the column.
    expect($request->audienceRef)->toBe('literature,public-information');
});

test('the older single committee field still works', function () {
    // Handsets in the field send this one, and so does every caller
    // written against fellowship_send_message().
    $request = MessageRequest::fromArray([
        'subject'   => 'One',
        'body'      => 'Committee.',
        'committee' => 'literature',
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->audienceType)->toBe(Message::AUDIENCE_COMMITTEE);
    expect($request->committees)->toBe(['literature']);
});

test('a repeated committee is named once', function () {
    $request = MessageRequest::fromArray([
        'subject'    => 'Twice',
        'body'       => 'Named.',
        'committees' => ['literature', 'literature'],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->committees)->toBe(['literature']);
});

test('too many committees are refused', function () {
    $result = MessageRequest::fromArray([
        'subject'    => 'Everyone, really',
        'body'       => 'Assembled out of parts.',
        'committees' => array_map(
            static fn(int $i): string => 'committee-' . $i,
            range(1, MessageRequest::MAX_COMMITTEES + 1),
        ),
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_too_many_committees');
});

test('committee names too long to store are refused rather than truncated', function () {
    // A silently shortened list is a send that reaches fewer people
    // than it says it did, and nothing downstream could tell.
    $result = MessageRequest::fromArray([
        'subject'    => 'Long',
        'body'       => 'Slugs.',
        'committees' => [str_repeat('a', 150), str_repeat('b', 150)],
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_too_many_committees');
});

test('a subject is required', function () {
    $result = MessageRequest::fromArray(['body' => 'No subject here.']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_no_subject');
});

test('a body is required', function () {
    $result = MessageRequest::fromArray(['subject' => 'Empty']);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_no_body');
});

test('markup is stripped rather than escaped', function () {
    // The app renders message text as text. There is no HTML surface
    // to escape into, and storing markup would create one later.
    $request = MessageRequest::fromArray([
        'subject' => 'Hello <script>alert(1)</script>',
        'body'    => '<b>Bold</b> and <img src=x onerror=y>',
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->subject)->not->toContain('<');
    expect($request->body)->not->toContain('<');
});

test('the body is capped in bytes', function () {
    // Bytes rather than characters, because bytes are what FCM counts.
    $request = MessageRequest::fromArray([
        'subject' => 'Long',
        'body'    => str_repeat('a', MessageRequest::BODY_MAX + 500),
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect(strlen($request->body))->toBeLessThanOrEqual(MessageRequest::BODY_MAX);
});

test('capping does not leave a partial utf8 sequence', function () {
    // substr on a UTF-8 string can split a multi-byte character, and
    // a body that json_encode refuses would fail at seal time — long
    // after anybody could connect it to this input.
    $request = MessageRequest::fromArray([
        'subject' => 'Accents',
        // Three-byte characters, so the cap lands mid-sequence.
        'body'    => str_repeat('あ', MessageRequest::BODY_MAX),
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect(mb_check_encoding($request->body, 'UTF-8'))->toBeTrue();
    expect(json_encode($request->body))->toBeString();
});

test('invalid addresses are dropped and duplicates collapse', function () {
    $request = MessageRequest::fromArray([
        'subject'       => 'Mixed',
        'body'          => 'Some good, some not.',
        'member_emails' => ['a@example.org', 'nonsense', 'A@EXAMPLE.ORG', ''],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);
    expect($request->memberEmails)->toBe(['a@example.org']);
});

test('too many named recipients is refused', function () {
    $emails = [];
    for ($i = 0; $i <= MessageRequest::MAX_EXPLICIT_RECIPIENTS; $i++) {
        $emails[] = 'member' . $i . '@example.org';
    }

    $result = MessageRequest::fromArray([
        'subject'       => 'Too many',
        'body'          => 'Use a committee.',
        'member_emails' => $emails,
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_too_many_recipients');
});
