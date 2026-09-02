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
    ) {
    }

    public function isRead(): bool
    {
        return $this->readAt !== null;
    }
}
