<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Messaging\AuditDetail;
use Fellowship\Messaging\Message;

/**
 * What Scrutiny is told about a sent message.
 *
 * <p>The rule is one line long and the tests are about the ways it can be
 * got wrong: <b>the subject is recorded and the body is not</b>. Both
 * send paths build their detail through this, so an assertion here holds
 * for a message sent from WordPress and for the same message sent from a
 * handset.</p>
 */

covers(\Fellowship\Messaging\AuditDetail::class);

function auditDetailMessage(
    string $subject = 'Committee meeting moved',
    string $body = 'The body is secret and must never appear in an audit row.',
    string $audienceType = Message::AUDIENCE_COMMITTEE,
    string $audienceRef = 'north',
): Message {
    return new Message(
        id: 42,
        uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        senderEmail: 'sender@example.org',
        senderMemberId: 7,
        senderName: 'Dave P',
        subject: $subject,
        body: $body,
        audienceType: $audienceType,
        audienceRef: $audienceRef,
        createdAt: 1788000000,
    );
}

test('the subject is recorded', function () {
    $detail = AuditDetail::forMessage(auditDetailMessage(), 'Message sent from Link', 11);

    expect($detail)->toContain(';subject:Committee meeting moved');
});

/**
 * The one that matters. An audit row is readable by anyone who may
 * audit, and the body is not theirs to read — it is in the message
 * table, under its own retention window.
 */
test('the body is never recorded', function () {
    $detail = AuditDetail::forMessage(auditDetailMessage(), 'Message sent from Link', 11);

    expect($detail)->not->toContain('secret');
    expect($detail)->not->toContain('must never appear');
});

test('it keeps the fields it always carried', function () {
    $detail = AuditDetail::forMessage(auditDetailMessage(), 'Message sent from WordPress', 11);

    expect($detail)->toStartWith('Message sent from WordPress;message:42');
    expect($detail)->toContain(';audience:committee');
    expect($detail)->toContain(';ref:north');
    expect($detail)->toContain(';recipients:11');
});

test('an audience with no ref omits the field', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(audienceType: Message::AUDIENCE_MEMBERS, audienceRef: ''),
        'Message sent from Link',
        3,
    );

    expect($detail)->not->toContain(';ref:');
});

test('trailing fields come before the subject', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(),
        'Message sent from Link',
        3,
        ['device' => 9],
    );

    expect($detail)->toContain(';device:9;subject:');
});

/**
 * A subject is member-typed text. One containing the delimiters would
 * otherwise forge a field — a message titled "x;recipients:1" reading
 * back as a send that reached one person.
 */
test('a subject cannot forge a field', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(subject: 'x;recipients:1;device:99'),
        'Message sent from Link',
        11,
    );

    expect($detail)->toContain(';recipients:11');
    expect($detail)->not->toContain(';recipients:1;');
    expect($detail)->not->toContain(';device:99');
    expect($detail)->toContain(';subject:x recipients 1 device 99');
});

/**
 * A detail column is read in a table cell and in a log line, and
 * neither survives an embedded newline honestly.
 */
test('newlines and control characters are flattened', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(subject: "first\nsecond\tthird\r\nfourth"),
        'Message sent from Link',
        1,
    );

    expect($detail)->not->toContain("\n");
    expect($detail)->not->toContain("\t");
    expect($detail)->toContain(';subject:first second third fourth');
});

/**
 * Scrutiny's detail column is VARCHAR(255), and a subject may be 200
 * characters. The whole row has to fit, and the structured fields are
 * the part that must survive — which is why the subject goes last and
 * is capped rather than the string being trimmed from the right.
 */
test('a long subject is capped and the row still fits', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(subject: str_repeat('a', 200)),
        'Message sent from WordPress',
        11,
        ['device' => 9],
    );

    expect(mb_strlen($detail))->toBeLessThanOrEqual(255);
    expect($detail)->toContain(';recipients:11');
    expect($detail)->toContain(';device:9');
    expect($detail)->toEndWith('…');
});

/**
 * A blank subject reads as a blank subject, not as a field with
 * nothing after it — which is indistinguishable from a row that was
 * truncated.
 */
test('a blank subject is omitted rather than left empty', function () {
    $detail = AuditDetail::forMessage(
        auditDetailMessage(subject: '   '),
        'Message sent from Link',
        1,
    );

    expect($detail)->not->toContain('subject');
    expect($detail)->toEndWith(';recipients:1');
});
