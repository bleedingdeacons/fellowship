<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The outcome of trying to resolve the handset behind a request.
 *
 * <b>Why this exists at all, given the 401 is deliberately
 * undifferentiated.</b> {@see CurrentDevice} answers null for every
 * refusal without distinguishing between them, because telling an
 * unauthenticated caller which of its guesses was closest is how enrolled
 * addresses get enumerated. That reasoning is exactly right for a caller
 * who has not proved anything.
 *
 * It does not apply to one who has. A request whose bearer token matched
 * a live device row has already demonstrated it holds a credential this
 * site issued; being told that the member behind that credential is no
 * longer one Fellowship will talk to reveals nothing it did not already
 * have, and cannot be used to probe a second address, because a token is
 * bound to the one device it was minted for.
 *
 * So exactly one case is separated out, and only that one:
 * {@see self::NOT_A_MEMBER}. Everything else — no header, a malformed
 * token, an unknown one, a revoked one — stays indistinguishable.
 *
 * What it buys is on the handset. Link showed every refusal as "could not
 * be reached", so a member whose record had changed was told to check
 * their signal about a phone that was working perfectly. Now it can say
 * which, and the two need completely different things from whoever is
 * reading them.
 */
final class DeviceResolution
{
    /** No device to be found, and deliberately no reason given. */
    public const UNAUTHENTICATED = 'unauthenticated';

    /**
     * The token was good and the person behind it is not, or no longer
     * is. The one refusal a member can act on.
     */
    public const NOT_A_MEMBER = 'not_a_member';

    private function __construct(
        public readonly ?Device $device,
        public readonly string $refusal,
    ) {
    }

    public static function found(Device $device): self
    {
        return new self($device, '');
    }

    public static function unauthenticated(): self
    {
        return new self(null, self::UNAUTHENTICATED);
    }

    public static function notAMember(): self
    {
        return new self(null, self::NOT_A_MEMBER);
    }

    public function succeeded(): bool
    {
        return $this->device !== null;
    }
}
