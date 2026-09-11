<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use WP_Error;

/**
 * A request to send, validated and capped before anything is stored.
 *
 * <b>The caps are not tidiness.</b> They are what makes the sealed
 * payload a known size, and the sealed payload has to fit inside FCM's
 * 4KB data-message limit alongside a 344-character wrapped key. Without a
 * ceiling on the body, the largest messages the API accepts would be
 * accepted, stored, and then silently fail to push — arriving only on
 * the next poll, or on a handset that never polls, not at all. See
 * {@see \Fellowship\Crypto\MessageSealer} for the measurement.
 *
 * Raising {@see BODY_MAX} means re-measuring against incompressible
 * text, not against prose.
 *
 * <b>Markup is stripped rather than escaped.</b> The app renders message
 * text as text; there is no HTML surface to escape into and storing
 * markup would only create one later.
 */
final class MessageRequest
{
    public const SUBJECT_MAX = 200;
    public const BODY_MAX = 2000;

    /** Most members one send may name explicitly. */
    public const MAX_EXPLICIT_RECIPIENTS = 200;

    /**
     * Most committees one send may name.
     *
     * Low on purpose: the slugs are stored joined in a 200-character
     * column, and a send that named more than a handful is a send that
     * wanted {@see Message::AUDIENCE_ALL} and should be refused as such
     * rather than assembled out of parts.
     */
    public const MAX_COMMITTEES = 10;

    /** How much room {@see Message} has for the joined slugs. */
    private const AUDIENCE_REF_MAX = 200;

    private function __construct(
        public readonly string $subject,
        public readonly string $body,
        public readonly string $audienceType,
        public readonly string $audienceRef,
        /** @var list<string> */
        public readonly array $memberEmails,
        public readonly int $replyToId,
        /**
         * The committee slugs this is addressed to, in the order given.
         *
         * {@see $audienceRef} is these joined with commas, which is what
         * is stored; this is what the resolver walks. One is derived from
         * the other, kept apart so nothing has to re-split a string it
         * just built.
         *
         * @var list<string>
         */
        public readonly array $committees = [],
    ) {
    }

    /**
     * Build from a caller's array, or explain the refusal.
     *
     * @param array<string, mixed> $input
     */
    public static function fromArray(array $input): self|WP_Error
    {
        $subject = self::text($input['subject'] ?? '', self::SUBJECT_MAX);
        $body    = self::text($input['body'] ?? '', self::BODY_MAX);

        if ($subject === '') {
            return new WP_Error('fellowship_no_subject', 'A message needs a subject.', ['status' => 400]);
        }

        if ($body === '') {
            return new WP_Error('fellowship_no_body', 'A message needs a body.', ['status' => 400]);
        }

        // `committees` is the shape; `committee` is the one it replaced
        // and is still accepted, because handsets in the field send it and
        // fellowship_send_message() callers wrote against it.
        $committees = self::committees($input['committees'] ?? $input['committee'] ?? []);
        $emails     = self::emails($input['member_emails'] ?? []);

        if (count($emails) > self::MAX_EXPLICIT_RECIPIENTS) {
            return new WP_Error(
                'fellowship_too_many_recipients',
                'A message may name at most ' . self::MAX_EXPLICIT_RECIPIENTS . ' members. Use a committee instead.',
                ['status' => 400],
            );
        }

        if (count($committees) > self::MAX_COMMITTEES) {
            return new WP_Error(
                'fellowship_too_many_committees',
                'A message may name at most ' . self::MAX_COMMITTEES . ' committees.',
                ['status' => 400],
            );
        }

        $ref = implode(',', $committees);

        // Refused rather than truncated, and this is the whole reason the
        // cap above is not the only check: a silently shortened list is a
        // send that reaches fewer people than it says it did, and nothing
        // downstream could tell. Storage is the constraint, so storage
        // gets to refuse.
        if (strlen($ref) > self::AUDIENCE_REF_MAX) {
            return new WP_Error(
                'fellowship_too_many_committees',
                'Those committee names are too long to record together. Send to fewer at once.',
                ['status' => 400],
            );
        }

        if ($committees !== [] && $emails !== []) {
            $audience = Message::AUDIENCE_MIXED;
        } elseif ($committees !== []) {
            $audience = Message::AUDIENCE_COMMITTEE;
        } elseif ($emails !== []) {
            $audience = Message::AUDIENCE_MEMBERS;
        } else {
            $audience = Message::AUDIENCE_ALL;
        }

        return new self(
            $subject,
            $body,
            $audience,
            $ref,
            $emails,
            max(0, (int) ($input['reply_to'] ?? 0)),
            $committees,
        );
    }

    /**
     * Normalise whatever a caller offered as committees into a list of
     * slugs: a single string, a comma-separated string, or an array.
     *
     * Deduplicated, because the resolver would produce one copy per
     * member anyway and a doubled slug in the stored ref would only
     * mislead whoever read it later.
     *
     * @return list<string>
     */
    private static function committees(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }

        if (!is_array($value)) {
            return [];
        }

        $slugs = [];

        foreach ($value as $slug) {
            if (is_int($slug)) {
                // A committee id. The resolver accepts either, and the
                // admin screen has ids to hand.
                $slug = (string) $slug;
            }

            if (!is_string($slug)) {
                continue;
            }

            $slug = trim($slug);

            if ($slug !== '' && !in_array($slug, $slugs, true)) {
                $slugs[] = $slug;
            }
        }

        return $slugs;
    }

    /**
     * Trim, strip markup, collapse control characters and cap.
     *
     * The cap is applied last and by bytes rather than characters,
     * because bytes are what FCM counts. `mb_strimwidth` would cut on a
     * character boundary but leave the byte length unknown; substr on a
     * UTF-8 string can split a multi-byte sequence, so the result is
     * trimmed back to a valid boundary afterwards.
     */
    private static function text(mixed $value, int $maxBytes): string
    {
        if (!is_string($value)) {
            return '';
        }

        $value = wp_strip_all_tags($value, true);
        // Anything below space except newline and tab, which a message
        // body may legitimately contain.
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
        $value = trim($value);

        if (strlen($value) <= $maxBytes) {
            return $value;
        }

        $cut = substr($value, 0, $maxBytes);
        // Drop a trailing partial UTF-8 sequence rather than storing a
        // string that json_encode will refuse later.
        while ($cut !== '' && !mb_check_encoding($cut, 'UTF-8')) {
            $cut = substr($cut, 0, -1);
        }

        return rtrim($cut);
    }

    /**
     * @return list<string>
     */
    private static function emails(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\s,;]+/', $value) ?: [];
        }

        if (!is_array($value)) {
            return [];
        }

        $emails = [];
        foreach ($value as $candidate) {
            if (!is_string($candidate)) {
                continue;
            }

            $email = strtolower(trim($candidate));
            if ($email === '' || is_email($email) === false) {
                continue;
            }

            $emails[$email] = true;
        }

        return array_keys($emails);
    }
}
