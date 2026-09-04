<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Auth\PasswordCredential;
use Fellowship\Auth\PasswordCredentialRepository;

/**
 * The credential store, in memory.
 *
 * The authenticator's interesting behaviour is all about *state* — a
 * lockout that accumulates, a token that is spent, a hash that is
 * rehashed — so the tests need a store that behaves like one rather than
 * a mock returning canned rows. This is why the repository is behind an
 * interface at all.
 */
final class InMemoryPasswordCredentialRepository implements PasswordCredentialRepository
{
    /** @var array<string, PasswordCredential> */
    public array $rows = [];

    public function find(string $email): ?PasswordCredential
    {
        return $this->rows[$email] ?? null;
    }

    public function findByResetTokenHash(string $tokenHash): ?PasswordCredential
    {
        foreach ($this->rows as $row) {
            if ($row->resetTokenHash !== '' && hash_equals($row->resetTokenHash, $tokenHash)) {
                return $row;
            }
        }

        return null;
    }

    public function upsertPasswordHash(string $email, string $passwordHash, int $now): void
    {
        // Matches the real repository's contract: a set or reset is a
        // fresh start, so the token is spent and any lockout is lifted.
        $this->rows[$email] = new PasswordCredential($email, $passwordHash, '', 0, 0, 0, $now);
    }

    public function storeResetToken(string $email, string $tokenHash, int $expiresAt, int $now): void
    {
        $existing = $this->rows[$email] ?? null;

        $this->rows[$email] = new PasswordCredential(
            $email,
            $existing?->passwordHash ?? '',
            $tokenHash,
            $expiresAt,
            $existing?->failedAttempts ?? 0,
            $existing?->lockedUntil ?? 0,
            $now,
        );
    }

    public function clearResetToken(string $email, int $now): void
    {
        $existing = $this->rows[$email] ?? null;
        if ($existing === null) {
            return;
        }

        $this->rows[$email] = new PasswordCredential(
            $email,
            $existing->passwordHash,
            '',
            0,
            $existing->failedAttempts,
            $existing->lockedUntil,
            $now,
        );
    }

    public function recordFailedAttempt(string $email, int $failedAttempts, int $lockedUntil, int $now): void
    {
        $existing = $this->rows[$email] ?? null;
        if ($existing === null) {
            // Never creates a row, as the real one promises: an unknown
            // address has no password to guess and must not be seeded
            // into the table by somebody guessing at it.
            return;
        }

        $this->rows[$email] = new PasswordCredential(
            $email,
            $existing->passwordHash,
            $existing->resetTokenHash,
            $existing->resetExpiresAt,
            $failedAttempts,
            $lockedUntil,
            $now,
        );
    }

    public function resetFailedAttempts(string $email, int $now): void
    {
        $this->recordFailedAttempt($email, 0, 0, $now);
    }

    public function delete(string $email): void
    {
        unset($this->rows[$email]);
    }
}
