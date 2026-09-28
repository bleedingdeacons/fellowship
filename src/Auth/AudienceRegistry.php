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
 * Built holding Link's, and nothing can replace that one: a plugin that
 * registered its own `link` would take over who Link's codes are issued
 * to. A second registration under any name already held is refused for
 * the same reason — two plugins disagreeing about one name is a wiring
 * mistake to be loud about, not a race for the last word.
 */
final class AudienceRegistry
{
    private const NAME_PATTERN = '/^[a-z0-9_-]{1,32}$/';

    /** @var array<string, SignInAudience> */
    private array $audiences = [];

    public function __construct(SignInAudience $link)
    {
        if ($link->name() !== LinkAudience::NAME) {
            throw new LogicException('The registry must be built with Link\'s audience.');
        }

        $this->audiences[LinkAudience::NAME] = $link;
    }

    public function register(SignInAudience $audience): void
    {
        $name = $audience->name();

        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            throw new LogicException(sprintf('"%s" is not a valid sign-in audience name.', $name));
        }

        if (isset($this->audiences[$name])) {
            throw new LogicException(sprintf('A sign-in audience named "%s" is already registered.', $name));
        }

        $this->audiences[$name] = $audience;
    }

    public function get(string $name): ?SignInAudience
    {
        return $this->audiences[$name] ?? null;
    }
}
