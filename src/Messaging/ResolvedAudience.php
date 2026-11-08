<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Who a message reaches, as member ids, and the kind of audience it was.
 *
 * The kind is what the Functions record on a message, in place of which committees:
 * a committee's slug says what it is.
 */
final class ResolvedAudience
{
    public const EVERYONE = 'everyone';
    public const MEMBERS = 'members';
    public const PART = 'part';
    public const MIXED = 'mixed';

    /**
     * @param list<int> $memberIds Sorted, never empty.
     */
    public function __construct(
        public readonly array $memberIds,
        public readonly string $kind,
    ) {
    }

    public static function kindOf(string $audienceType): string
    {
        return match ($audienceType) {
            Message::AUDIENCE_ALL       => self::EVERYONE,
            Message::AUDIENCE_COMMITTEE => self::PART,
            Message::AUDIENCE_MIXED     => self::MIXED,
            default                     => self::MEMBERS,
        };
    }
}
