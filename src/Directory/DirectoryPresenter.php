<?php

declare(strict_types=1);

namespace Fellowship\Directory;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;
use Unity\Committees\Interfaces\CommitteeRepository;
use Unity\Groups\Interfaces\GroupRepository;
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
 *
 * <b>Everybody else is, whether or not they use Link.</b> The only test
 * is {@see MemberGate::isAuthorised()}, which asks whether a member has
 * a usable email address — that is, whether they *could* enrol, not
 * whether they have. Someone who has never installed the app is listed
 * and can be written to; the message waits on the server and arrives
 * when they enrol. Filtering the list to enrolled handsets would make the
 * address book change shape as people came and went, and would quietly
 * make a member unreachable for the ordinary reason that they had not got
 * round to installing anything.
 *
 * <b>Home group and GSR travel with the name, and no contact details
 * do.</b> A first name alone does not identify anybody in an intergroup
 * with several Daves, which is the whole reason Hand shows a home group
 * beside its own member list. GSR is there because it is the reason a
 * member is most often written to. Neither is a contact detail, and the
 * paragraph above still holds exactly as written.
 */
final class DirectoryPresenter
{
    /**
     * @param GroupRepository|null $groups Unity ships headless, so the
     *     group repository is not guaranteed to be bound. Null means the
     *     list is built without home groups rather than not at all.
     */
    /**
     * Group id to title, built on first use. Null until then, so a
     * request that lists no members never asks Unity for groups at all.
     *
     * @var array<int, string>|null
     */
    private ?array $groupTitles = null;

    public function __construct(
        private readonly MemberRepository $members,
        private readonly CommitteeRepository $committees,
        private readonly MemberGate $gate,
        private readonly ?GroupRepository $groups = null,
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
                'id'    => $member->getId(),
                'name'  => $name,
                'group' => $this->groupTitle($member->getHomeGroup()),
                // A bool rather than a label, so the app decides how to
                // say it and a translation never has to come from here.
                'gsr'   => $member->isGSR(),
            ];
        }

        usort($listed, static fn(array $a, array $b): int => strcasecmp((string) $a['name'], (string) $b['name']));

        return $listed;
    }

    /**
     * One group's title, or empty when it cannot be named.
     *
     * <b>Resolved from a map built once, not with a query per member.</b>
     * `getHomeGroup()` gives an id, and calling `findById()` inside the
     * member loop would be one round trip per member on an endpoint that
     * returns the whole address book — the N+1 that turns a list of a few
     * hundred people into a few hundred queries.
     *
     * Empty is a perfectly ordinary answer: a member need not have a home
     * group recorded, and a group can be deleted while members still
     * point at it. The app leaves the line out rather than showing a
     * blank one.
     */
    private function groupTitle(int $id): string
    {
        if ($id <= 0 || $this->groups === null) {
            return '';
        }

        if ($this->groupTitles === null) {
            $this->groupTitles = [];

            foreach ($this->groups->findAll() as $group) {
                $this->groupTitles[$group->getId()] = trim($group->getTitle());
            }
        }

        return $this->groupTitles[$id] ?? '';
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
