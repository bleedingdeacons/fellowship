<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Finding the Link device behind a Firebase ID token, and whether a device is
 * still live.
 *
 * {@see FirebaseDevices} is the one that asks Firebase. This is what the
 * {@see \Fellowship\Auth\IdentityBroker} depends on, so another plugin's tests
 * can stand a Link device in without signing a token or answering Firestore.
 */
interface FirebaseDeviceLookup
{
    public function resolve(string $idToken): FirebaseDeviceResolution;

    public function isLive(string $deviceId): bool;
}
