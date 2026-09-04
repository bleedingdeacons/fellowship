<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use LogicException;
use wpdb;

use function dbDelta;

/**
 * $wpdb-backed implementation of {@see PasswordCredentialRepository}.
 *
 * Schema is created via dbDelta on plugin activation (see install()).
 * One row per member email; holds only hashed secrets (bcrypt password
 * hash, SHA-256 reset-token hash) plus the lockout counters — never any
 * raw password or raw token.
 *
 * Writes use INSERT … ON DUPLICATE KEY UPDATE so the first password
 * reset for a member (who has no row yet) and every later change go
 * through the same code path, keyed on the email primary key.
 *
 * Every write here guards wpdb::prepare() against null, which is why the
 * SQL goes into a local before reaching query() rather than being nested
 * inline. prepare() returns null only when the query carries no
 * placeholders or the arguments do not match them — a coding error, never
 * a runtime condition — so the guards throw rather than skipping the
 * write. These statements are the source of truth for password sign-in;
 * silently issuing no query at all would leave a caller believing a
 * password or lockout counter had been stored when it had not.
 */
final class WpdbPasswordCredentialRepository implements PasswordCredentialRepository
{
    public const TABLE_SUFFIX = 'fellowship_credentials';

    public function __construct(private readonly wpdb $wpdb)
    {
    }

    /**
     * @return literal-string
     *
     * wpdb::prepare() only accepts a literal-string query, and every query in
     * this class interpolates this table name. PHPStan types $wpdb->prefix as
     * a plain string so it cannot derive that on its own — the annotation
     * asserts it. It holds: the prefix comes from wp-config.php and the suffix
     * is a class constant, so no part of this is reachable from user input.
     */
    public static function tableName(wpdb $wpdb): string
    {
        // Asserted on the prefix rather than on the concatenation: PHPStan
        // infers the joined string as non-falsy-string, which literal-string
        // is not a subtype of, so a @var on the result is rejected outright.
        /** @var literal-string $prefix */
        $prefix = $wpdb->prefix;

        return $prefix . self::TABLE_SUFFIX;
    }

    /**
     * Idempotent: safe to call on every activation. dbDelta diffs against
     * the live schema and only applies changes.
     */
    public static function install(wpdb $wpdb): void
    {
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        $table   = self::tableName($wpdb);
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            email VARCHAR(254) NOT NULL,
            password_hash VARCHAR(255) NOT NULL DEFAULT '',
            reset_token_hash CHAR(64) NOT NULL DEFAULT '',
            reset_expires_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
            failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            locked_until BIGINT UNSIGNED NOT NULL DEFAULT 0,
            updated_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY  (email),
            KEY reset_token_hash (reset_token_hash)
        ) {$charset};";

        dbDelta($sql);
    }

    public function find(string $email): ?PasswordCredential
    {
        $table = self::tableName($this->wpdb);
        $row = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT email, password_hash, reset_token_hash, reset_expires_at,
                    failed_attempts, locked_until, updated_at
               FROM {$table}
              WHERE email = %s
              LIMIT 1",
            $email,
        ), ARRAY_A);

        return is_array($row) ? $this->hydrate($row) : null;
    }

    public function findByResetTokenHash(string $tokenHash): ?PasswordCredential
    {
        // An empty hash would otherwise match every reset-free row; refuse
        // it outright so a blank token can never resolve to a credential.
        if ($tokenHash === '') {
            return null;
        }

        $table = self::tableName($this->wpdb);
        $row = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT email, password_hash, reset_token_hash, reset_expires_at,
                    failed_attempts, locked_until, updated_at
               FROM {$table}
              WHERE reset_token_hash = %s
              LIMIT 1",
            $tokenHash,
        ), ARRAY_A);

        return is_array($row) ? $this->hydrate($row) : null;
    }

    public function upsertPasswordHash(string $email, string $passwordHash, int $now): void
    {
        $table = self::tableName($this->wpdb);

        // Setting a password clears any pending reset token and unlocks the
        // account in the same statement — a successful set/reset is a clean
        // slate.
        $sql = $this->wpdb->prepare(
            "INSERT INTO {$table}
                 (email, password_hash, reset_token_hash, reset_expires_at,
                  failed_attempts, locked_until, updated_at)
             VALUES (%s, %s, '', 0, 0, 0, %d)
             ON DUPLICATE KEY UPDATE
                 password_hash = VALUES(password_hash),
                 reset_token_hash = '',
                 reset_expires_at = 0,
                 failed_attempts = 0,
                 locked_until = 0,
                 updated_at = VALUES(updated_at)",
            $email,
            $passwordHash,
            $now,
        );

        if ($sql === null) {
            throw new LogicException('Failed to prepare the password upsert query.');
        }

        $this->wpdb->query($sql);
    }

    public function storeResetToken(string $email, string $tokenHash, int $expiresAt, int $now): void
    {
        $table = self::tableName($this->wpdb);

        $sql = $this->wpdb->prepare(
            "INSERT INTO {$table}
                 (email, reset_token_hash, reset_expires_at, updated_at)
             VALUES (%s, %s, %d, %d)
             ON DUPLICATE KEY UPDATE
                 reset_token_hash = VALUES(reset_token_hash),
                 reset_expires_at = VALUES(reset_expires_at),
                 updated_at = VALUES(updated_at)",
            $email,
            $tokenHash,
            $expiresAt,
            $now,
        );

        if ($sql === null) {
            throw new LogicException('Failed to prepare the reset-token store query.');
        }

        $this->wpdb->query($sql);
    }

    public function clearResetToken(string $email, int $now): void
    {
        $table = self::tableName($this->wpdb);

        $sql = $this->wpdb->prepare(
            "UPDATE {$table}
                SET reset_token_hash = '', reset_expires_at = 0, updated_at = %d
              WHERE email = %s",
            $now,
            $email,
        );

        if ($sql === null) {
            throw new LogicException('Failed to prepare the reset-token clear query.');
        }

        $this->wpdb->query($sql);
    }

    public function recordFailedAttempt(string $email, int $failedAttempts, int $lockedUntil, int $now): void
    {
        $table = self::tableName($this->wpdb);

        // UPDATE only — an unknown email has no password to guess, so we
        // never create a row for it (that would leak existence and let an
        // attacker seed the table).
        $sql = $this->wpdb->prepare(
            "UPDATE {$table}
                SET failed_attempts = %d, locked_until = %d, updated_at = %d
              WHERE email = %s",
            $failedAttempts,
            $lockedUntil,
            $now,
            $email,
        );

        if ($sql === null) {
            throw new LogicException('Failed to prepare the failed-attempt query.');
        }

        $this->wpdb->query($sql);
    }

    public function resetFailedAttempts(string $email, int $now): void
    {
        $table = self::tableName($this->wpdb);

        $sql = $this->wpdb->prepare(
            "UPDATE {$table}
                SET failed_attempts = 0, locked_until = 0, updated_at = %d
              WHERE email = %s",
            $now,
            $email,
        );

        if ($sql === null) {
            throw new LogicException('Failed to prepare the attempt-reset query.');
        }

        $this->wpdb->query($sql);
    }

    public function delete(string $email): void
    {
        $this->wpdb->delete(self::tableName($this->wpdb), ['email' => $email], ['%s']);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): PasswordCredential
    {
        return new PasswordCredential(
            (string) $row['email'],
            (string) $row['password_hash'],
            (string) $row['reset_token_hash'],
            (int) $row['reset_expires_at'],
            (int) $row['failed_attempts'],
            (int) $row['locked_until'],
            (int) $row['updated_at'],
        );
    }
}
