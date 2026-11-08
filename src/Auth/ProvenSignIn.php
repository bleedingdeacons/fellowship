<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A fresh Firebase sign-in, and what it proves about a person.
 *
 * Either an address, from Google or Apple, or a member id, from a Unity password
 * Fellowship checked itself. Never both.
 */
final class ProvenSignIn
{
    private function __construct(
        /** The Firebase uid: what the Functions see as the caller. */
        public readonly string $uid,
        public readonly string $email,
        public readonly int $memberId,
    ) {
    }

    public static function byEmail(string $uid, string $email): self
    {
        return new self($uid, strtolower(trim($email)), 0);
    }

    public static function byMemberId(string $uid, int $memberId): self
    {
        return new self($uid, '', $memberId);
    }
}
