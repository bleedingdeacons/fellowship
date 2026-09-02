<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;
use Unity\Committees\Interfaces\CommitteeRepository;
use Unity\Members\Interfaces\Member;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Turns an audience into the actual list of members a message goes to.
 *
 * <b>Every path ends at the same gate.</b> A committee's membership, a
 * hand-typed list of addresses and "everyone" are three different
 * questions to Unity and one answer to Fellowship: a member who may be
 * messaged. Resolving them separately and applying the gate once at the
 * end is what stops "send to committee" quietly reaching somebody that
 * "send to this person" would have refused.
 *
 * <b>Committees include their descendants.</b> Unity models committees as
 * a tree, and a message to Public Information that skipped its
 * sub-committees would be a surprise to whoever sent it — the sender is
 * naming a part of the intergroup, not a row in a table. Unity's
 * `memberIdsIn()` already defaults this way; it is stated here because it
 * is a decision, not an accident.
 */
final class RecipientResolver
{
    public function __construct(
        private readonly MemberRepository $members,
        private readonly CommitteeRepository $committees,
        private readonly MemberGate $gate,
    ) {
    }

    /**
     * Resolve a request to the members it should reach.
     *
     * The sender is excluded: a message arriving in its own author's
     * inbox reads as a delivery failure the first time and as noise
     * every time after. A reply still reaches the person being replied
     * to, because they are a recipient of the reply and not its sender.
     *
     * @return list<array{email: string, member_id: int}>
     */
    public function resolve(MessageRequest $request, string $senderEmail = ''): array
    {
        $members = match ($request->audienceType) {
            Message::AUDIENCE_COMMITTEE => $this->fromCommittee($request->audienceRef),
            Message::AUDIENCE_MEMBERS   => $this->fromEmails($request->memberEmails),
            default                     => $this->everyone(),
        };

        $senderEmail = strtolower(trim($senderEmail));

        $resolved = [];
        foreach ($members as $member) {
            if (!$this->gate->isAuthorised($member)) {
                continue;
            }

            $email = strtolower(trim($member->getPersonalEmail()));
            if ($email === '' || $email === $senderEmail) {
                continue;
            }

            // Keyed by email so a member reachable through two branches of
            // a committee tree still gets one copy.
            $resolved[$email] = ['email' => $email, 'member_id' => $member->getId()];
        }

        return array_values($resolved);
    }

    /**
     * @return list<Member>
     */
    private function fromCommittee(string $committee): array
    {
        $committee = trim($committee);
        if ($committee === '') {
            return [];
        }

        // A slug or a numeric id, because both are natural to a caller:
        // the admin screen has the id to hand and another plugin calling
        // fellowship_send_message() will have written the slug. Unity's
        // repository accepts either.
        $reference = ctype_digit($committee) ? (int) $committee : $committee;

        $memberIds = $this->committees->memberIdsIn($reference, true);

        $members = [];
        foreach ($memberIds as $memberId) {
            $member = $this->members->findById((int) $memberId);
            if ($member !== null) {
                $members[] = $member;
            }
        }

        return $members;
    }

    /**
     * @param list<string> $emails
     * @return list<Member>
     */
    private function fromEmails(array $emails): array
    {
        $members = [];
        foreach ($emails as $email) {
            $member = $this->members->findByEmail(strtolower(trim($email)));
            if ($member !== null) {
                $members[] = $member;
            }
        }

        return $members;
    }

    /**
     * Every member Unity holds.
     *
     * The gate then removes those with no usable email, and the
     * dispatcher only pushes to those with a handset — so "everyone"
     * means everyone reachable, not everyone on the books. Sending to
     * this audience is guarded by a capability rather than by size: a
     * cap here would silently truncate the one send where completeness
     * is the point.
     *
     * @return list<Member>
     */
    private function everyone(): array
    {
        $members = $this->members->findAll();
        return array_values(array_filter($members, static fn($m): bool => $m instanceof Member));
    }
}
