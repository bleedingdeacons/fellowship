<?php

declare(strict_types=1);

namespace Fellowship\Sync;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;
use Fellowship\Firebase\AdminFunctions;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Logger\HasLogger;
use Unity\Members\Interfaces\Member;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Cuts off devices on Firebase when their member stops being admitted.
 *
 * Firebase can't notice for itself, because the member list stays in WordPress.
 *
 * - <b>A member deleted from Unity</b> has their devices removed straight away.
 *   This is what an erasure reaches.
 * - <b>Every day</b>, each member with a live device is put through the gate.
 *   That catches everything else, such as an address taken off a record.
 *
 * <b>The daily check won't cut off a lot of people at once.</b> Revoking is final,
 * and a member list that came back short or wrong for a moment would otherwise cut
 * off the whole fellowship. If an implausible share would go, it does nothing and
 * logs an error for somebody to look at.
 */
final class MemberWatch
{
    use HasLogger;

    public const CRON_HOOK = 'fellowship_member_watch';

    /** The most members one daily check will revoke, whatever the share. */
    private const ALWAYS_ALLOWED = 3;

    /** The largest share of members with devices one daily check will revoke. */
    private const MAX_SHARE = 0.25;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly MemberRepository $members,
        private readonly MemberGate $gate,
        private readonly FirestoreClient $firestore,
        private readonly AdminFunctions $functions,
        private readonly RetentionSync $retention,
    ) {
    }

    public function register(): void
    {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK);
        }

        add_action(self::CRON_HOOK, [$this, 'daily']);
        add_action('unity/member_deleted', [$this, 'memberDeleted'], 10, 2);
    }

    /** @param mixed $member Unity's deleted member, when it has one to give. */
    public function memberDeleted(mixed $postId, mixed $member = null): void
    {
        if (!$member instanceof Member || !$this->functions->isConfigured()) {
            return;
        }

        try {
            $this->functions->revokeMember((int) $member->getId(), remove: true);
        } catch (FirebaseUnavailable) {
            // The daily check can't catch this one, because the member is no longer
            // there to be checked against. An error, so somebody sees it.
            self::logError('A deleted member\'s devices could not be removed from Firebase', [
                'memberId' => (int) $member->getId(),
            ]);
        }
    }

    public function daily(): void
    {
        $this->retention->push();

        if (!$this->firestore->isConfigured() || !$this->functions->isConfigured()) {
            return;
        }

        try {
            $withDevices = array_values(array_unique($this->firestore->liveDeviceMemberIds()));
        } catch (FirebaseUnavailable) {
            self::logWarning('The daily member check could not read devices from Firebase');

            return;
        }

        $refused = array_values(array_filter(
            $withDevices,
            fn(int $memberId): bool => !$this->gate->isAuthorised($this->members->findById($memberId)),
        ));

        if ($refused === []) {
            return;
        }

        $allowed = max(self::ALWAYS_ALLOWED, (int) floor(count($withDevices) * self::MAX_SHARE));
        if (count($refused) > $allowed) {
            self::logError('The daily member check would cut off too many members, so it did nothing', [
                'refused'     => count($refused),
                'withDevices' => count($withDevices),
                'allowed'     => $allowed,
            ]);

            return;
        }

        foreach ($refused as $memberId) {
            try {
                $this->functions->revokeMember($memberId);
                self::logInfo('A member is no longer admitted; their devices were revoked', ['memberId' => $memberId]);
            } catch (FirebaseUnavailable) {
                self::logWarning('A member\'s devices could not be revoked; the next check will try again', [
                    'memberId' => $memberId,
                ]);
            }
        }
    }
}
