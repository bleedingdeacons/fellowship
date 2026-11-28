<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Devices\FirebaseDevice;
use Fellowship\Devices\FirebaseDeviceLookup;
use Fellowship\Devices\FirebaseDeviceResolution;

/**
 * Link devices on Firebase, held in memory and found by a stand-in ID token.
 *
 * For the broker's session hand-off: Freedom's tests autoload this too. A
 * token is shaped like a JWT (three dot-separated parts) so it passes the
 * same first check a real one does, and means nothing beyond that.
 */
final class InMemoryFirebaseDevices implements FirebaseDeviceLookup
{
    /** @var array<string, FirebaseDevice> token => device */
    private array $byToken = [];

    /** @var array<string, bool> device id => live */
    private array $live = [];

    /** Answer the ID token a signed-in phone on this device would present. */
    public function add(
        int $memberId,
        string $email,
        string $platform = 'android',
        string $deviceId = '',
    ): string {
        $deviceId = $deviceId !== '' ? $deviceId : 'd_' . bin2hex(random_bytes(16));
        $token = 'header.' . $deviceId . '.signature';

        $this->byToken[$token] = new FirebaseDevice($deviceId, $memberId, $email, $platform);
        $this->live[$deviceId] = true;

        return $token;
    }

    public function revoke(string $deviceId): void
    {
        $this->live[$deviceId] = false;
    }

    /** @return list<string> */
    public function liveIds(): array
    {
        return array_keys(array_filter($this->live));
    }

    public function resolve(string $idToken): FirebaseDeviceResolution
    {
        $device = $this->byToken[$idToken] ?? null;

        return $device !== null && ($this->live[$device->id] ?? false)
            ? FirebaseDeviceResolution::found($device)
            : FirebaseDeviceResolution::unauthenticated();
    }

    public function isLive(string $deviceId): bool
    {
        return $this->live[$deviceId] ?? false;
    }
}
