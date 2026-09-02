<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

use Unity\Members\Interfaces\Member;
use Unity\Members\Interfaces\MemberRepository;

/**
 * The single answer to "may this person use Link?".
 *
 * One object rather than a rule written out in four places, because it
 * is consulted at four moments that must agree: enrolling a handset,
 * authenticating each request from one, deciding who a message may be
 * addressed to, and deciding whose handsets a message actually reaches.
 * A gate that disagreed with itself between enrolment and delivery would
 * enrol people who never receive anything, or deliver to people who
 * should no longer be reachable.
 *
 * <b>The rule is deliberately thin: a Unity member with a valid personal
 * email.</b> Link is the fellowship's own address book, not a privileged
 * tool — a member is entitled to be reachable by it, and adding a role
 * requirement would mean a newcomer who has just given their email
 * cannot be messaged by the intergroup that took it.
 *
 * The email is the whole identity. OAuth verifies that the person at the
 * handset controls an address; this decides whether that address belongs
 * to a member. Neither half is sufficient alone, which is why enrolment
 * needs both.
 */
final class MemberGate
{
    public function __construct(private readonly MemberRepository $members)
    {
    }

    /**
     * The member this verified email belongs to, or null when the address
     * is not a member's or the member may not use Link.
     */
    public function authorisedMember(string $email): ?Member
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return null;
        }

        $member = $this->members->findByEmail($email);
        if ($member === null) {
            return null;
        }

        return $this->isAuthorised($member) ? $member : null;
    }

    public function isAuthorised(?Member $member): bool
    {
        if ($member === null) {
            return false;
        }

        $email = strtolower(trim($member->getPersonalEmail()));

        return $email !== '' && is_email($email) !== false;
    }
}
