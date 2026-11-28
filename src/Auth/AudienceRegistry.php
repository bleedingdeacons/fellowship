<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use LogicException;

/**
 * The audiences a browser sign-in may be done for.
 *
 * `link` is reserved and serves nothing. It was Link's own browser sign-in,
 * which ended when Link moved to Firebase: a code for it would go to whichever
 * app on the phone claimed `link://`. A sign-in state or code stored without
 * an audience was Link's too, so it reads as this name and is refused.
 *
 * A second registration under any name already held is refused, for the same
 * reason the reserved name is: two plugins disagreeing about one name is a
 * wiring mistake to be loud about, not a race for the last word.
 */
final class AudienceRegistry
{
    /** Link's old browser sign-in. Nothing may register it, and nothing is served for it. */
    public const RESERVED = 'link';

    private const NAME_PATTERN = '/^[a-z0-9_-]{1,32}$/';

    /** @var array<string, SignInAudience> */
    private array $audiences = [];

    public function register(SignInAudience $audience): void
    {
        $name = $audience->name();

        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            throw new LogicException(sprintf('"%s" is not a valid sign-in audience name.', $name));
        }

        if ($name === self::RESERVED || isset($this->audiences[$name])) {
            throw new LogicException(sprintf('A sign-in audience named "%s" is already registered.', $name));
        }

        $this->audiences[$name] = $audience;
    }

    public function get(string $name): ?SignInAudience
    {
        return $this->audiences[$name] ?? null;
    }
}
