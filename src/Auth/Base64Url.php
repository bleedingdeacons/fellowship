<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * base64url, as JWTs and JWKs use it: '+' and '/' swapped for '-' and
 * '_', and the '=' padding dropped.
 */
trait Base64Url
{
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecodeOrNull(string $data): ?string
    {
        $pad = strlen($data) % 4;
        if ($pad > 0) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    protected function base64UrlDecode(string $data): string
    {
        return $this->base64UrlDecodeOrNull($data) ?? '';
    }
}
