<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use RuntimeException;

/**
 * Firebase couldn't be asked, as opposed to answering no.
 *
 * Those two must never be confused. A device that isn't found is refused. A
 * Google outage is a bad minute, and revoking or signing out over it would be far
 * worse than what it protects against.
 *
 * An admin Function refusing lands here too, carrying its reason and its words, so
 * that a screen can tell the difference and say what the Function said.
 */
final class FirebaseUnavailable extends RuntimeException
{
    public function __construct(
        string $message = '',
        public readonly string $reason = '',
        public readonly string $refusal = '',
    ) {
        parent::__construct($message);
    }
}
