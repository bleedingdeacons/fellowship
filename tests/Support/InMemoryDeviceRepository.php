<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Devices\Device;
use Fellowship\Devices\DeviceRepository;

/**
 * Enrolled handsets, in memory.
 *
 * The controllers and the dispatcher spend most of their time deciding
 * *which* devices a thing applies to — live ones, one member's, the
 * revoked one that must not come back — so a double that actually holds
 * state is the point. A mock returning canned lists would assert that the
 * test knows what it wrote.
 *
 * The one behaviour worth copying exactly from the wpdb implementation is
 * that {@see findByTokenHash()} and the two list methods never return a
 * revoked row. That is the whole revocation mechanism: a revoked handset
 * is refused because it cannot be found, not because anything downstream
 * checks a flag.
 */
final class InMemoryDeviceRepository implements DeviceRepository
{
    /** @var array<int, Device> */
    public array $rows = [];

    private int $nextId = 1;

    public function create(
        string $tokenHash,
        string $memberEmail,
        int $memberId,
        string $label,
        string $platform,
        string $publicKey,
        string $pushProvider,
        string $pushToken,
        int $now,
    ): Device {
        $device = new Device(
            id: $this->nextId++,
            memberEmail: $memberEmail,
            memberId: $memberId,
            label: $label,
            platform: $platform,
            publicKey: $publicKey,
            pushProvider: $pushProvider,
            pushToken: $pushToken,
            createdAt: $now,
        );

        $this->rows[$device->id] = $device;
        $this->hashes[$tokenHash] = $device->id;

        return $device;
    }

    /** @var array<string, int> */
    private array $hashes = [];

    public function findByTokenHash(string $tokenHash): ?Device
    {
        $id = $this->hashes[$tokenHash] ?? null;
        if ($id === null) {
            return null;
        }

        $device = $this->rows[$id] ?? null;

        // Revoked rows are invisible here, exactly as they are in the
        // wpdb implementation. This is the revocation.
        return $device !== null && !$device->isRevoked() ? $device : null;
    }

    public function findById(int $id): ?Device
    {
        return $this->rows[$id] ?? null;
    }

    public function findByMemberEmail(string $memberEmail): array
    {
        return array_values(array_filter(
            $this->rows,
            static fn(Device $d): bool => $d->memberEmail === $memberEmail && !$d->isRevoked(),
        ));
    }

    public function findAllLive(): array
    {
        return array_values(array_filter($this->rows, static fn(Device $d): bool => !$d->isRevoked()));
    }

    public function list(int $limit, int $offset): array
    {
        return array_slice(array_values($this->rows), $offset, $limit);
    }

    public function countAll(): int
    {
        return count($this->rows);
    }

    public function touchLastSeen(int $id, int $now): void
    {
        $this->replace($id, ['lastSeenAt' => $now]);
    }

    public function updatePush(int $id, string $pushProvider, string $pushToken): void
    {
        $this->replace($id, ['pushProvider' => $pushProvider, 'pushToken' => $pushToken]);
    }

    public function updatePublicKey(int $id, string $publicKey): bool
    {
        if (!isset($this->rows[$id])) {
            return false;
        }

        // A rotated key clears the fault: the handset is saying it can
        // read again, which is the only way the server ever finds out.
        $this->replace($id, ['publicKey' => $publicKey, 'keyFaultAt' => null]);

        return true;
    }

    public function markKeyFault(int $id, int $now): void
    {
        $this->replace($id, ['keyFaultAt' => $now]);
    }

    public function clearKeyFault(int $id): void
    {
        $this->replace($id, ['keyFaultAt' => null]);
    }

    public function revoke(int $id, int $now): bool
    {
        if (!isset($this->rows[$id]) || $this->rows[$id]->isRevoked()) {
            return false;
        }

        $this->replace($id, ['revokedAt' => $now]);

        return true;
    }

    public function revokeAllForMember(string $memberEmail, int $now): int
    {
        $count = 0;

        foreach ($this->rows as $device) {
            if ($device->memberEmail === $memberEmail && !$device->isRevoked()) {
                $this->replace($device->id, ['revokedAt' => $now]);
                $count++;
            }
        }

        return $count;
    }

    public function remove(int $id): bool
    {
        if (!isset($this->rows[$id])) {
            return false;
        }

        unset($this->rows[$id]);

        return true;
    }

    /**
     * Device is readonly, so a change is a new one with the named fields
     * replaced.
     *
     * @param array<string, mixed> $changes
     */
    private function replace(int $id, array $changes): void
    {
        $existing = $this->rows[$id] ?? null;
        if ($existing === null) {
            return;
        }

        $this->rows[$id] = new Device(
            id: $existing->id,
            memberEmail: $changes['memberEmail'] ?? $existing->memberEmail,
            memberId: $changes['memberId'] ?? $existing->memberId,
            label: $changes['label'] ?? $existing->label,
            platform: $changes['platform'] ?? $existing->platform,
            publicKey: $changes['publicKey'] ?? $existing->publicKey,
            pushProvider: $changes['pushProvider'] ?? $existing->pushProvider,
            pushToken: $changes['pushToken'] ?? $existing->pushToken,
            createdAt: $existing->createdAt,
            lastSeenAt: $changes['lastSeenAt'] ?? $existing->lastSeenAt,
            revokedAt: array_key_exists('revokedAt', $changes) ? $changes['revokedAt'] : $existing->revokedAt,
            keyFaultAt: array_key_exists('keyFaultAt', $changes) ? $changes['keyFaultAt'] : $existing->keyFaultAt,
        );
    }
}
