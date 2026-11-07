<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * One sent message, as the log can know it.
 *
 * <b>No subject, no body and no committee names.</b> Messages are end-to-end
 * encrypted, so none of those are held anywhere this site can read. What's left is
 * who sent it, what kind of audience it had, and how far it has got.
 */
final class LoggedMessage
{
    public const AUDIENCE_EVERYONE = 'everyone';
    public const AUDIENCE_PART = 'part';
    public const AUDIENCE_MEMBERS = 'members';
    public const AUDIENCE_MIXED = 'mixed';

    public function __construct(
        public readonly int $id,
        public readonly int $senderMemberId,
        public readonly string $audience,
        public readonly int $recipients,
        public readonly int $received,
        public readonly int $read,
        public readonly int $createdAt,
    ) {
    }
}
