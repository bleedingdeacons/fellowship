<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\LinkDevice;
use Fellowship\Devices\LinkDevices;

/**
 * Handsets read from Firestore, and cut off through the admin Functions.
 *
 * Reads go straight to Firestore. Changes go through the Functions, because cutting
 * a device off also has to revoke its Firebase user, which only they do.
 */
final class FirestoreLinkDevices implements LinkDevices
{
    /** No key and no token: the screen doesn't show them, so they aren't fetched for it. */
    private const FIELDS = ['memberId', 'platform', 'label', 'pushToken', 'keyFault', 'status', 'createdAt', 'lastSeenAt', 'revokedAt'];

    public function __construct(
        private readonly FirestoreClient $firestore,
        private readonly AdminFunctions $functions,
    ) {
    }

    public function page(int $limit, int $offset): array
    {
        return array_map(
            static fn(array $row): LinkDevice => self::device($row['id'], $row['fields']),
            $this->firestore->query('devices', self::FIELDS, 'createdAt', $limit, $offset),
        );
    }

    public function find(string $id): ?LinkDevice
    {
        $fields = $this->firestore->get('devices/' . $id);

        return $fields === null ? null : self::device($id, $fields);
    }

    public function revoke(string $id): void
    {
        $this->functions->revoke($id);
    }

    public function remove(string $id): void
    {
        $this->functions->remove($id);
    }

    /** @param array<string, mixed> $fields */
    private static function device(string $id, array $fields): LinkDevice
    {
        return new LinkDevice(
            $id,
            is_int($fields['memberId'] ?? null) ? $fields['memberId'] : 0,
            is_string($fields['platform'] ?? null) ? $fields['platform'] : '',
            is_string($fields['label'] ?? null) ? $fields['label'] : '',
            is_string($fields['pushToken'] ?? null) && $fields['pushToken'] !== '',
            ($fields['keyFault'] ?? false) === true,
            ($fields['status'] ?? '') !== 'live',
            FirestoreClient::epoch($fields['createdAt'] ?? null),
            FirestoreClient::epoch($fields['lastSeenAt'] ?? null),
            FirestoreClient::epoch($fields['revokedAt'] ?? null),
        );
    }
}
