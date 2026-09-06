<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Builds the `detail` string Scrutiny records for a sent message.
 *
 * <b>The subject is recorded. The body is not.</b> That is the whole
 * point of this class existing rather than the two send paths each
 * building their own string: they must agree, or the audit trail says one
 * thing about a message sent from WordPress and another about the same
 * message sent from a handset.
 *
 * <p>Why the subject and not the body. An audit trail that records only
 * that "a message was sent to eleven people" cannot answer the question
 * it exists to answer — which of the messages was it — without opening
 * the message table, which is exactly the thing an auditor reviewing
 * access should not have to do. The subject is the line the recipients
 * saw first and the shortest thing that identifies a message. The body is
 * where the substance is, and Scrutiny does not need a second copy of it:
 * it is already in a table, with its own retention window.</p>
 *
 * <p><b>A subject is member-typed text and may carry personal data.</b>
 * The AuditLogger contract asks callers to keep raw PII out of the
 * detail, and this deliberately relaxes that for one field, because an
 * unidentifiable audit entry is its own kind of failure. What follows
 * from it: the subject is treated as hostile text — delimiters stripped
 * so it cannot forge a field, newlines flattened, and length capped —
 * and it inherits the audit log's retention rather than the message
 * table's.</p>
 */
final class AuditDetail
{
    /**
     * Longest subject an audit detail will carry.
     *
     * Scrutiny's `detail` column is VARCHAR(255). The structured part
     * below runs to about 90 characters at its wordiest, so 120 leaves
     * room to spare — and the subject goes last, so a subject that is
     * somehow longer still cannot push a structured field off the end.
     */
    private const MAX_SUBJECT_LENGTH = 120;

    /**
     * @param string $origin      Where the send came from, for a reader.
     * @param int    $recipients  How many members it reached.
     * @param array<string, string|int> $extra Trailing fields, in order.
     */
    public static function forMessage(
        Message $message,
        string $origin,
        int $recipients,
        array $extra = [],
    ): string {
        $detail = $origin
            . ';message:' . $message->id
            . ';audience:' . $message->audienceType
            . ($message->audienceRef !== '' ? ';ref:' . $message->audienceRef : '')
            . ';recipients:' . $recipients;

        foreach ($extra as $key => $value) {
            $detail .= ';' . $key . ':' . $value;
        }

        $subject = self::sanitiseSubject($message->subject);

        // Last, and only when there is one. A message with a blank
        // subject should read as one, not as a field with nothing after
        // it — which is indistinguishable from a truncated entry.
        return $subject === '' ? $detail : $detail . ';subject:' . $subject;
    }

    /**
     * Make a member-typed subject safe to sit in a delimited field.
     *
     * <p>Semicolons and colons are what separate one field from the next,
     * so a subject containing them could otherwise forge one — a message
     * titled "x;recipients:1" would read back as a send that reached one
     * person. Replaced rather than dropped, so the reader can see that
     * something was there.</p>
     *
     * <p>Control characters and newlines go the same way: a detail column
     * is read in a table cell and in a log line, and neither survives an
     * embedded newline honestly.</p>
     */
    private static function sanitiseSubject(string $subject): string
    {
        $clean = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $subject) ?? '';
        $clean = str_replace([';', ':'], ' ', $clean);
        $clean = preg_replace('/\s+/u', ' ', $clean) ?? '';
        $clean = trim($clean);

        if (mb_strlen($clean) > self::MAX_SUBJECT_LENGTH) {
            $clean = mb_substr($clean, 0, self::MAX_SUBJECT_LENGTH - 1) . '…';
        }

        return $clean;
    }
}
