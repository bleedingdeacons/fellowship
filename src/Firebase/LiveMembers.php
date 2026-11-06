<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Which members have a live device on Firebase.
 *
 * Kept for a few minutes, because the directory asks once per read for the whole
 * list. So a member who has just enrolled can take that long to become selectable.
 */
final class LiveMembers
{
    private const TRANSIENT = 'fellowship_firebase_live_members';

    private const CACHE_SECONDS = 300;

    public function __construct(private readonly FirestoreClient $firestore)
    {
    }

    /**
     * The members with a live device, keyed by id, or null when Firebase couldn't
     * be asked. Null means "unknown" and never "nobody".
     *
     * @return array<int, true>|null
     */
    public function memberIds(): ?array
    {
        if (!$this->firestore->isConfigured()) {
            return [];
        }

        $cached = get_transient(self::TRANSIENT);
        if (is_array($cached)) {
            return $cached;
        }

        try {
            $ids = array_fill_keys($this->firestore->liveDeviceMemberIds(), true);
        } catch (FirebaseUnavailable) {
            return null;
        }

        set_transient(self::TRANSIENT, $ids, self::CACHE_SECONDS);

        return $ids;
    }
}
