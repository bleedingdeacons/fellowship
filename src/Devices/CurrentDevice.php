<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\DeviceTokenMinter;
use Unity\Members\Interfaces\Member;
use WP_REST_Request;

/**
 * Resolves the handset behind an authenticated request, and the member
 * it belongs to.
 *
 * <b>Two checks, not one.</b> A valid bearer token proves the request
 * came from a handset this site enrolled. It does not prove the person
 * behind it is still someone Link may be used by — Unity is the
 * authority on that, and it changes without anybody telling Fellowship.
 * So the token finds the row, and {@see MemberGate} then re-resolves the
 * email to a live member on every single request.
 *
 * The cost is one member lookup per call. The alternative is a handset
 * that keeps working after its member is removed from Unity, until
 * somebody remembers to revoke the device by hand — which is precisely
 * the thing nobody remembers.
 */
final class CurrentDevice
{
    /**
     * How stale last_seen_at may get before a request refreshes it.
     *
     * Not every request, because a handset polling for messages would
     * otherwise write to the devices table several times a minute for a
     * column nothing reads more precisely than "today". Five minutes
     * keeps the admin list honest at a fraction of the writes.
     */
    private const TOUCH_INTERVAL_SECONDS = 300;

    public function __construct(
        private readonly DeviceRepository $devices,
        private readonly DeviceTokenMinter $minter,
        private readonly MemberGate $gate,
    ) {
    }

    /**
     * The device this request authenticates as, or null.
     *
     * Null covers every refusal without distinguishing between them — no
     * header, a malformed token, an unknown one, a revoked one, a member
     * who no longer qualifies. The app has nothing useful to do
     * differently with any of them, and telling an unauthenticated caller
     * which of its guesses was closest is how enrolled emails get
     * enumerated.
     */
    public function fromRequest(WP_REST_Request $request): ?Device
    {
        $token = $this->minter->bearerFrom((string) $request->get_header('authorization'));
        if ($token === '' || !$this->minter->looksLikeToken($token)) {
            return null;
        }

        $device = $this->devices->findByTokenHash($this->minter->hash($token));
        if ($device === null) {
            return null;
        }

        if ($this->gate->authorisedMember($device->memberEmail) === null) {
            return null;
        }

        $now = time();
        if ($now - $device->lastSeenAt >= self::TOUCH_INTERVAL_SECONDS) {
            $this->devices->touchLastSeen($device->id, $now);
        }

        return $device;
    }

    /**
     * The member behind an authenticated request, or null.
     *
     * Resolved through the same gate the device check uses, so the answer
     * cannot disagree with whether the request was allowed at all.
     */
    public function memberFor(Device $device): ?Member
    {
        return $this->gate->authorisedMember($device->memberEmail);
    }
}
