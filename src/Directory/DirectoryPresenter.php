<?php

declare(strict_types=1);

namespace Fellowship\Directory;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;
use Unity\Committees\Interfaces\CommitteeRepository;
use Unity\Members\Interfaces\Member;
use Unity\Members\Interfaces\MemberRepository;

/**
 * The address book Link shows when a member composes.
 *
 * <b>Anonymous names, and no contact details at all.</b> A member picks
 * a recipient from this list and Fellowship does the addressing; the app
 * never learns anybody's email address or telephone number, so a stolen
 * handset yields a list of first names rather than the intergroup's
 * contact database. That is also why the identifier the app sends back
 * is an opaque member id rather than an address — see
 * {@see \Fellowship\Rest\MessageController}, which resolves ids to
 * addresses server-side.
 *
 * <b>Members who have opted out of being listed are not here.</b> Unity's
 * `showMemberProfile()` is a member's own decision about appearing in
 * directories, and a messaging app is a directory whatever else it is.
 * They can still receive a committee message — being contactable by the
 * intergroup is not the same as being browsable by everyone.
 */
final class DirectoryPresenter
{
    public function __construct(
        private readonly MemberRepository $members,
        private readonly CommitteeRepository $committees,
        private readonly MemberGate $gate,
    ) {
    }

    /**
     * @return array{members: list<array<string, mixed>>, committees: list<array<string, mixed>>}
     */
    public function forApp(bool $includeCommittees): array
    {
        return [
            'members'    => $this->memberList(),
            'committees' => $includeCommittees ? $this->committeeList() : [],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function memberList(): array
    {
        $listed = [];

        foreach ($this->members->findAll() as $member) {
            if (!$member instanceof Member || !$this->gate->isAuthorised($member)) {
                continue;
            }

            if (!$member->showMemberProfile()) {
                continue;
            }

            $name = trim($member->getAnonymousName());
            if ($name === '') {
                // A member with no anonymous name has nothing that can be
                // shown without breaking anonymity, so they are left out
                // rather than listed as a blank row or, worse, by email.
                continue;
            }

            $listed[] = [
                'id'   => $member->getId(),
                'name' => $name,
            ];
        }

        usort($listed, static fn(array $a, array $b): int => strcasecmp((string) $a['name'], (string) $b['name']));

        return $listed;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function committeeList(): array
    {
        $listed = [];

        foreach ($this->committees->findAll() as $committee) {
            $listed[] = [
                'slug'   => $committee->getSlug(),
                'name'   => $committee->getName(),
                'parent' => $committee->getParentId(),
            ];
        }

        usort($listed, static fn(array $a, array $b): int => strcasecmp((string) $a['name'], (string) $b['name']));

        return $listed;
    }
}
