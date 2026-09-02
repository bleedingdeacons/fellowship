<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * One message, as stored.
 *
 * <b>Held in plain text, deliberately.</b> The body is sealed on its way
 * out to each handset, but the stored copy is readable by this site —
 * that is what lets an admin compose to a committee, lets the message
 * log be reviewed, and lets Scrutiny audit what was sent to whom. The
 * alternative was end-to-end encryption the server cannot open, which
 * would have cost all three. See the plugin README for the trade as it
 * was actually decided.
 *
 * What follows from that: the database row is personal data. The
 * retention sweep is not housekeeping, it is the thing that keeps this
 * defensible.
 *
 * <b>The sender is an anonymous name, not a legal one.</b> Unity holds
 * both; this stores what a member is willing to be known as in the
 * fellowship, because a message list is read by people who have no
 * business learning surnames.
 */
final class Message
{
    /** Addressed to an explicit list of members. */
    public const AUDIENCE_MEMBERS = 'members';

    /** Addressed to everyone on a committee, resolved at send time. */
    public const AUDIENCE_COMMITTEE = 'committee';

    /** Addressed to every member with a live handset. */
    public const AUDIENCE_ALL = 'all';

    public const AUDIENCES = [self::AUDIENCE_MEMBERS, self::AUDIENCE_COMMITTEE, self::AUDIENCE_ALL];

    public function __construct(
        public readonly int $id,
        public readonly string $uuid,
        public readonly string $senderEmail,
        public readonly int $senderMemberId,
        public readonly string $senderName,
        public readonly string $subject,
        public readonly string $body,
        public readonly string $audienceType,
        /**
         * What the audience type points at: a committee slug for
         * AUDIENCE_COMMITTEE, empty otherwise.
         *
         * The resolved recipient list is *not* stored here — it lives in
         * the recipients table, one row per member. A committee's
         * membership changes, and a message has to keep saying who it
         * actually reached rather than re-deriving a different answer
         * later.
         */
        public readonly string $audienceRef,
        public readonly int $createdAt,
        /**
         * The message this one replies to, or 0.
         *
         * A flat reply pointer rather than a thread id: v1 shows a reply
         * under what it answers and nothing deeper. A real thread model
         * can be derived from this later; a thread id invented now would
         * have to be guessed for every existing row.
         */
        public readonly int $replyToId = 0,
        /**
         * The handset that sent it, or 0 for a message composed in
         * WordPress admin.
         *
         * Kept so a send can be traced back to a device that has since
         * been revoked — the row survives revocation for exactly this
         * kind of question.
         */
        public readonly int $senderDeviceId = 0,
    ) {
    }

    public function isReply(): bool
    {
        return $this->replyToId > 0;
    }

    public function cameFromApp(): bool
    {
        return $this->senderDeviceId > 0;
    }
}
