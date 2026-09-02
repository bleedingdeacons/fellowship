<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

use function get_transient;
use function set_transient;

/**
 * A fixed-window counter kept in transients.
 *
 * Guards the unauthenticated enrolment routes and the authenticated send
 * route. Not a security boundary on its own — a distributed caller gets
 * a fresh bucket per IP — but it is what stops one handset in a retry
 * loop from filling the message table.
 */
final class RateLimiter
{
    /** True when this call should be refused; counts the call otherwise. */
    public function overLimit(string $key, int $max, int $windowSeconds): bool
    {
        $windowSeconds = max(1, $windowSeconds);
        $window = (int) floor(time() / $windowSeconds);
        $bucket = 'fship_rl_' . md5($key . '|' . $window);

        $count = (int) get_transient($bucket);
        if ($count >= $max) {
            return true;
        }

        // Keep the counter a little past the window so a burst straddling
        // the boundary is still counted.
        set_transient($bucket, $count + 1, $windowSeconds * 2);
        return false;
    }

    public function clientIp(): string
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : 'unknown';
    }
}
