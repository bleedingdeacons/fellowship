<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Outcome of {@see PasswordAuthenticator::completeReset()}.
 *
 * Distinguishes the three cases the REST layer maps to different HTTP
 * responses: the token was bad/expired/spent (400), the token was fine but
 * the chosen password fails the {@see PasswordPolicy} (422, with a reason),
 * or success (200 + a session for the returned email).
 */
final class PasswordResetResult
{
    public const OK             = 'ok';
    public const INVALID_TOKEN  = 'invalid_token';
    public const WEAK_PASSWORD  = 'weak_password';

    private function __construct(
        public readonly string $status,
        public readonly string $email,
        public readonly string $message,
    ) {
    }

    public static function ok(string $email): self
    {
        return new self(self::OK, $email, '');
    }

    public static function invalidToken(): self
    {
        return new self(self::INVALID_TOKEN, '', '');
    }

    public static function weakPassword(string $message): self
    {
        return new self(self::WEAK_PASSWORD, '', $message);
    }

    public function isOk(): bool
    {
        return $this->status === self::OK;
    }
}
