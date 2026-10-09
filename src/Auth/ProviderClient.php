<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use InvalidArgumentException;

/**
 * One OAuth client: the id and secret an audience registered with a
 * provider. See {@see BringsOwnClient}.
 *
 * The secret is plaintext here and only here, on its way into a provider
 * for one request. Whoever keeps it stores it encrypted.
 */
final class ProviderClient
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $clientSecret,
    ) {
        if (trim($clientId) === '') {
            // An empty id would build a provider that sends Google no
            // client at all. Null from clientFor() is how an audience says
            // "use Fellowship's".
            throw new InvalidArgumentException('A provider client needs a client id.');
        }
    }
}
