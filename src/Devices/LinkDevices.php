<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Firebase\FirebaseUnavailable;

/**
 * The enrolled handsets, for the Devices screen.
 *
 * Every method can throw {@see FirebaseUnavailable}, because the answer lives in
 * Firebase. A screen must say that it couldn't ask, never that there are no devices.
 */
interface LinkDevices
{
    /**
     * Newest first.
     *
     * @return list<LinkDevice>
     *
     * @throws FirebaseUnavailable
     */
    public function page(int $limit, int $offset): array;

    /** @throws FirebaseUnavailable */
    public function find(string $id): ?LinkDevice;

    /**
     * Cut the handset off and keep the record.
     *
     * @throws FirebaseUnavailable
     */
    public function revoke(string $id): void;

    /**
     * Delete the record, and with it the evidence the handset ever existed.
     *
     * @throws FirebaseUnavailable
     */
    public function remove(string $id): void;
}
