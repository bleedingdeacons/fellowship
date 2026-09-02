<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Decides which redirect targets the sign-in flow may hand a code to.
 *
 * An allow-list, because the value arrives on an unauthenticated route
 * and ends up as a `Location:` header carrying a credential. Anything
 * that is not recognisably the Link app or a developer's loopback
 * listener is refused outright rather than sanitised — there is no
 * partially-acceptable redirect here.
 */
final class DeviceRedirectValidator
{
    /** The Link app's own custom scheme, registered in its manifest. */
    public const APP_SCHEME = 'link';

    public const APP_HOST = 'auth';

    private const LOOPBACK_HOSTS = ['127.0.0.1', '[::1]', '::1'];

    /** Below 1024 needs root to bind, so a developer's listener never legitimately sits there. */
    private const MIN_LOOPBACK_PORT = 1024;

    public function isAllowed(string $uri): bool
    {
        $uri = trim($uri);
        if ($uri === '') {
            return false;
        }

        // A fragment can carry a second URI past naive parsing, and we
        // never need one. Same for credentials in the authority.
        if (str_contains($uri, '#') || str_contains($uri, '@')) {
            return false;
        }

        $parts = parse_url($uri);
        if (!is_array($parts) || !isset($parts['scheme'])) {
            return false;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host   = strtolower((string) ($parts['host'] ?? ''));

        if ($scheme === self::APP_SCHEME) {
            // No port and no query: the app's own callback is a fixed
            // address, and we append the code ourselves.
            return $host === self::APP_HOST
                && !isset($parts['port'])
                && !isset($parts['query']);
        }

        if ($scheme === 'http' && in_array($host, self::LOOPBACK_HOSTS, true)) {
            $port = $parts['port'] ?? 0;
            return is_int($port)
                && $port >= self::MIN_LOOPBACK_PORT
                && $port <= 65535
                && !isset($parts['query']);
        }

        return false;
    }

    /** @param array<string, string> $params */
    public function withParams(string $uri, array $params): string
    {
        if ($params === []) {
            return $uri;
        }

        return rtrim($uri, '?&') . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
