<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * One member's copy of one message.
 *
 * <b>Per member, not per device.</b> A member with a phone and a tablet
 * has one row, and both handsets fetch it. Read state is therefore the
 * member's, which is what a person means by "I have read that" — marking
 * it read on the phone should not leave it bold on the tablet.
 *
 * The cost is that Fellowship cannot say which handset read it. Nothing
 * needs to know, and the alternative — a row per device — would multiply
 * the table by the number of devices and make "unread" a question with
 * several answers.
 */
final class Recipient
{
    public function __construct(
        public readonly int $id,
        public readonly int $messageId,
        public readonly string $memberEmail,
        public readonly int $memberId,
        public readonly int $createdAt,
        public readonly ?int $readAt = null,
        /**
         * When a push for this row was last accepted by FCM, or null.
         *
         * "Accepted by FCM" is as far as this can honestly go: FCM
         * answering 200 means it took the message, not that a handset
         * received it. Treating it as delivery would make the admin list
         * lie on exactly the occasions somebody is looking at it because
         * a message did not arrive.
         */
        public readonly ?int $pushedAt = null,
        /**
         * When one of this member's handsets said it had opened the
         * message, or null.
         *
         * <b>This is the delivery {@see $pushedAt} cannot be.</b> It is
         * written only by a handset that has the message in its hands —
         * see {@see \Fellowship\Rest\MessageController::markReceived()} —
         * and never inferred from a fetch: a message that arrived by push
         * is never fetched again, so a server that counted fetches would
         * report the fastest deliveries as the ones that never arrived.
         *
         * Like read state it is the member's rather than the handset's.
         * The first of their devices to open it sets it, and later ones
         * leave it alone.
         */
        public readonly ?int $receivedAt = null,
    ) {
    }

    public function isRead(): bool
    {
        return $this->readAt !== null;
    }

    /**
     * Whether it reached the member, counting a read as proof it did.
     *
     * A handset can open a message and lose the acknowledgement on the
     * way back; once the member reads it, the read is the receipt.
     */
    public function isReceived(): bool
    {
        return $this->receivedAt !== null || $this->readAt !== null;
    }
}
