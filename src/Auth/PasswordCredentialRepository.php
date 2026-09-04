<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Persistence for member password credentials.
 *
 * Keyed by the member's email (normalised lowercase). A row is created
 * lazily the first time a member requests a password reset or sets a
 * password — most Fellowship members never have one, since OAuth is the default
 * sign-in path.
 *
 * Bound in the container to {@see WpdbPasswordCredentialRepository}; split
 * behind an interface so the authenticator can be unit-tested against an
 * in-memory fake.
 */
interface PasswordCredentialRepository
{
    /** Load the credential for an email, or null if none exists. */
    public function find(string $email): ?PasswordCredential;

    /**
     * Load the credential holding the given reset-token hash, or null.
     * The hash is the SHA-256 hex of the raw token from the reset link.
     */
    public function findByResetTokenHash(string $tokenHash): ?PasswordCredential;

    /**
     * Set (or replace) the password hash for an email, creating the row if
     * needed. Also clears any pending reset token and unlocks the account —
     * a successful set/reset is a fresh start.
     */
    public function upsertPasswordHash(string $email, string $passwordHash, int $now): void;

    /**
     * Store a pending reset-token hash + expiry for an email, creating the
     * row if needed. Leaves any existing password hash untouched.
     */
    public function storeResetToken(string $email, string $tokenHash, int $expiresAt, int $now): void;

    /** Clear any pending reset token for an email. */
    public function clearResetToken(string $email, int $now): void;

    /**
     * Persist the running failed-attempt count and lockout deadline for an
     * existing credential. Never creates a row — unknown emails have no
     * password to guess and must not be seeded into the table.
     */
    public function recordFailedAttempt(string $email, int $failedAttempts, int $lockedUntil, int $now): void;

    /** Zero the failed-attempt count and lockout after a successful login. */
    public function resetFailedAttempts(string $email, int $now): void;

    /**
     * Delete the credential for an email. Used to erase this GDPR-protected
     * personal data when the member is deleted. No-op if no row exists.
     */
    public function delete(string $email): void;
}
