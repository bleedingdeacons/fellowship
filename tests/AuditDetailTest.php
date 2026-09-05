<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
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
 *
 * @covers \Fellowship\Messaging\AuditDetail
 */
final class AuditDetailTest extends TestCase
{
    private static function message(
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

    public function testTheSubjectIsRecorded(): void
    {
        $detail = AuditDetail::forMessage(self::message(), 'Message sent from Link', 11);

        self::assertStringContainsString(';subject:Committee meeting moved', $detail);
    }

    /**
     * The one that matters. An audit row is readable by anyone who may
     * audit, and the body is not theirs to read — it is in the message
     * table, under its own retention window.
     */
    public function testTheBodyIsNeverRecorded(): void
    {
        $detail = AuditDetail::forMessage(self::message(), 'Message sent from Link', 11);

        self::assertStringNotContainsString('secret', $detail);
        self::assertStringNotContainsString('must never appear', $detail);
    }

    public function testItKeepsTheFieldsItAlwaysCarried(): void
    {
        $detail = AuditDetail::forMessage(self::message(), 'Message sent from WordPress', 11);

        self::assertStringStartsWith('Message sent from WordPress;message:42', $detail);
        self::assertStringContainsString(';audience:committee', $detail);
        self::assertStringContainsString(';ref:north', $detail);
        self::assertStringContainsString(';recipients:11', $detail);
    }

    public function testAnAudienceWithNoRefOmitsTheField(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(audienceType: Message::AUDIENCE_MEMBERS, audienceRef: ''),
            'Message sent from Link',
            3,
        );

        self::assertStringNotContainsString(';ref:', $detail);
    }

    public function testTrailingFieldsComeBeforeTheSubject(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(),
            'Message sent from Link',
            3,
            ['device' => 9],
        );

        self::assertStringContainsString(';device:9;subject:', $detail);
    }

    /**
     * A subject is member-typed text. One containing the delimiters would
     * otherwise forge a field — a message titled "x;recipients:1" reading
     * back as a send that reached one person.
     */
    public function testASubjectCannotForgeAField(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(subject: 'x;recipients:1;device:99'),
            'Message sent from Link',
            11,
        );

        self::assertStringContainsString(';recipients:11', $detail);
        self::assertStringNotContainsString(';recipients:1;', $detail);
        self::assertStringNotContainsString(';device:99', $detail);
        self::assertStringContainsString(';subject:x recipients 1 device 99', $detail);
    }

    /**
     * A detail column is read in a table cell and in a log line, and
     * neither survives an embedded newline honestly.
     */
    public function testNewlinesAndControlCharactersAreFlattened(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(subject: "first\nsecond\tthird\r\nfourth"),
            'Message sent from Link',
            1,
        );

        self::assertStringNotContainsString("\n", $detail);
        self::assertStringNotContainsString("\t", $detail);
        self::assertStringContainsString(';subject:first second third fourth', $detail);
    }

    /**
     * Scrutiny's detail column is VARCHAR(255), and a subject may be 200
     * characters. The whole row has to fit, and the structured fields are
     * the part that must survive — which is why the subject goes last and
     * is capped rather than the string being trimmed from the right.
     */
    public function testALongSubjectIsCappedAndTheRowStillFits(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(subject: str_repeat('a', 200)),
            'Message sent from WordPress',
            11,
            ['device' => 9],
        );

        self::assertLessThanOrEqual(255, mb_strlen($detail));
        self::assertStringContainsString(';recipients:11', $detail);
        self::assertStringContainsString(';device:9', $detail);
        self::assertStringEndsWith('…', $detail);
    }

    /**
     * A blank subject reads as a blank subject, not as a field with
     * nothing after it — which is indistinguishable from a row that was
     * truncated.
     */
    public function testABlankSubjectIsOmittedRatherThanLeftEmpty(): void
    {
        $detail = AuditDetail::forMessage(
            self::message(subject: '   '),
            'Message sent from Link',
            1,
        );

        self::assertStringNotContainsString('subject', $detail);
        self::assertStringEndsWith(';recipients:1', $detail);
    }
}
