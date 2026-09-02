<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRequest;
use PHPUnit\Framework\TestCase;
use WP_Error;

/**
 * Validation, and the caps that keep a sealed payload inside FCM's limit.
 */
final class MessageRequestTest extends TestCase
{
    public function testACommitteeAudienceIsRecognised(): void
    {
        $request = MessageRequest::fromArray([
            'subject'   => 'Meeting moved',
            'body'      => 'To the 14th.',
            'committee' => 'public-information',
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertSame(Message::AUDIENCE_COMMITTEE, $request->audienceType);
        self::assertSame('public-information', $request->audienceRef);
    }

    public function testNamedMembersAreRecognised(): void
    {
        $request = MessageRequest::fromArray([
            'subject'       => 'Rota',
            'body'          => 'Can you cover Thursday?',
            'member_emails' => ['A@Example.org', 'b@example.org'],
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertSame(Message::AUDIENCE_MEMBERS, $request->audienceType);
        self::assertSame(['a@example.org', 'b@example.org'], $request->memberEmails);
    }

    public function testNoAudienceMeansEveryone(): void
    {
        $request = MessageRequest::fromArray(['subject' => 'Notice', 'body' => 'Read this.']);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertSame(Message::AUDIENCE_ALL, $request->audienceType);
    }

    public function testACommitteeAndNamedMembersTogetherAreRefused(): void
    {
        // "This committee, and also these four people" reads as one
        // intention but stores as two, and the resulting recipient list
        // cannot be explained back to the sender.
        $result = MessageRequest::fromArray([
            'subject'       => 'Both',
            'body'          => 'At once.',
            'committee'     => 'literature',
            'member_emails' => ['a@example.org'],
        ]);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('fellowship_ambiguous_audience', $result->get_error_code());
    }

    public function testASubjectIsRequired(): void
    {
        $result = MessageRequest::fromArray(['body' => 'No subject here.']);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('fellowship_no_subject', $result->get_error_code());
    }

    public function testABodyIsRequired(): void
    {
        $result = MessageRequest::fromArray(['subject' => 'Empty']);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('fellowship_no_body', $result->get_error_code());
    }

    public function testMarkupIsStrippedRatherThanEscaped(): void
    {
        // The app renders message text as text. There is no HTML surface
        // to escape into, and storing markup would create one later.
        $request = MessageRequest::fromArray([
            'subject' => 'Hello <script>alert(1)</script>',
            'body'    => '<b>Bold</b> and <img src=x onerror=y>',
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertStringNotContainsString('<', $request->subject);
        self::assertStringNotContainsString('<', $request->body);
    }

    public function testTheBodyIsCappedInBytes(): void
    {
        // Bytes rather than characters, because bytes are what FCM counts.
        $request = MessageRequest::fromArray([
            'subject' => 'Long',
            'body'    => str_repeat('a', MessageRequest::BODY_MAX + 500),
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertLessThanOrEqual(MessageRequest::BODY_MAX, strlen($request->body));
    }

    public function testCappingDoesNotLeaveAPartialUtf8Sequence(): void
    {
        // substr on a UTF-8 string can split a multi-byte character, and
        // a body that json_encode refuses would fail at seal time — long
        // after anybody could connect it to this input.
        $request = MessageRequest::fromArray([
            'subject' => 'Accents',
            // Three-byte characters, so the cap lands mid-sequence.
            'body'    => str_repeat('あ', MessageRequest::BODY_MAX),
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertTrue(mb_check_encoding($request->body, 'UTF-8'));
        self::assertIsString(json_encode($request->body));
    }

    public function testInvalidAddressesAreDroppedAndDuplicatesCollapse(): void
    {
        $request = MessageRequest::fromArray([
            'subject'       => 'Mixed',
            'body'          => 'Some good, some not.',
            'member_emails' => ['a@example.org', 'nonsense', 'A@EXAMPLE.ORG', ''],
        ]);

        self::assertInstanceOf(MessageRequest::class, $request);
        self::assertSame(['a@example.org'], $request->memberEmails);
    }

    public function testTooManyNamedRecipientsIsRefused(): void
    {
        $emails = [];
        for ($i = 0; $i <= MessageRequest::MAX_EXPLICIT_RECIPIENTS; $i++) {
            $emails[] = 'member' . $i . '@example.org';
        }

        $result = MessageRequest::fromArray([
            'subject'       => 'Too many',
            'body'          => 'Use a committee.',
            'member_emails' => $emails,
        ]);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('fellowship_too_many_recipients', $result->get_error_code());
    }
}
