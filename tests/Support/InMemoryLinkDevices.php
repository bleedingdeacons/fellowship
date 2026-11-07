<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Devices\LinkDevice;
use Fellowship\Devices\LinkDevices;
use Fellowship\Firebase\FirebaseUnavailable;

/** Handsets in a list. Set {@see $down} and every call fails as Firebase being out would. */
final class InMemoryLinkDevices implements LinkDevices
{
    /** @var array<string, LinkDevice> */
    public array $rows = [];

    public bool $down = false;

    /** @var list<array{limit: int, offset: int}> */
    public array $asked = [];

    public function add(
        string $id = 'd_abc',
        int $memberId = 7,
        string $label = 'Pixel 6a',
        bool $hasPushToken = true,
        bool $keyFault = false,
        bool $revoked = false,
    ): void {
        $this->rows[$id] = new LinkDevice(
            $id,
            $memberId,
            'android',
            $label,
            $hasPushToken,
            $keyFault,
            $revoked,
            1788000000,
            1788000050,
            $revoked ? 1788000100 : 0,
        );
    }

    public function page(int $limit, int $offset): array
    {
        $this->check();
        $this->asked[] = ['limit' => $limit, 'offset' => $offset];

        return array_slice(array_values($this->rows), $offset, $limit);
    }

    public function find(string $id): ?LinkDevice
    {
        $this->check();

        return $this->rows[$id] ?? null;
    }

    public function revoke(string $id): void
    {
        $this->check();

        $device = $this->rows[$id];
        $this->rows[$id] = new LinkDevice(
            $id,
            $device->memberId,
            $device->platform,
            $device->label,
            false,
            $device->keyFault,
            true,
            $device->createdAt,
            $device->lastSeenAt,
            1788000100,
        );
    }

    public function remove(string $id): void
    {
        $this->check();

        unset($this->rows[$id]);
    }

    private function check(): void
    {
        if ($this->down) {
            throw new FirebaseUnavailable('Firestore could not be reached.');
        }
    }
}
