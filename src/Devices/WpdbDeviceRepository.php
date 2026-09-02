<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

use RuntimeException;
use wpdb;

use function dbDelta;

/**
 * Enrolled handsets, in a table of their own.
 *
 * <b>Nothing here is encrypted, and that is the point.</b> The row holds
 * a token HMAC (not the token), an email, and a *public* key. There is no
 * secret in it to protect: the private half of the keypair is in the
 * handset's own keystore and was never sent. Reach's device table has to
 * encrypt its payload key column because the server issued that key and
 * holds it; Fellowship's does not, because the server never had one.
 */
final class WpdbDeviceRepository implements DeviceRepository
{
    public const TABLE_SUFFIX = 'fellowship_devices';

    /**
     * @return literal-string
     *
     * Asserted on the prefix rather than on the concatenation: PHPStan
     * infers the joined string as non-falsy-string, which literal-string
     * is not a subtype of, so a @var on the result is rejected outright.
     * wpdb::prepare() will not accept anything else, and it is right not
     * to — a table name that could carry a value is an injection.
     */
    public static function tableName(wpdb $wpdb): string
    {
        /** @var literal-string $prefix */
        $prefix = $wpdb->prefix;

        return $prefix . self::TABLE_SUFFIX;
    }

    public function __construct(private readonly wpdb $wpdb)
    {
    }

    public static function install(wpdb $wpdb): void
    {
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        $table   = self::tableName($wpdb);
        $charset = $wpdb->get_charset_collate();

        // public_key is TEXT rather than VARCHAR: an RSA-4096 SPKI is
        // around 736 base64 characters and a VARCHAR(1024) would sit
        // uncomfortably close to a limit nobody would think to check
        // before raising MIN_BITS.
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            token_hash CHAR(64) NOT NULL,
            member_email VARCHAR(254) NOT NULL,
            member_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            label VARCHAR(200) NOT NULL DEFAULT '',
            platform VARCHAR(32) NOT NULL DEFAULT '',
            public_key TEXT NULL,
            push_provider VARCHAR(16) NOT NULL DEFAULT '',
            push_token VARCHAR(512) NOT NULL DEFAULT '',
            key_fault_at BIGINT UNSIGNED NULL,
            created_at BIGINT UNSIGNED NOT NULL,
            last_seen_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
            revoked_at BIGINT UNSIGNED NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY token_hash (token_hash),
            KEY member_email (member_email),
            KEY revoked_at (revoked_at)
        ) {$charset};";

        dbDelta($sql);
    }

    public function create(
        string $tokenHash,
        string $memberEmail,
        int $memberId,
        string $label,
        string $platform,
        string $publicKey,
        string $pushProvider,
        string $pushToken,
        int $now,
    ): Device {
        $table = self::tableName($this->wpdb);

        $inserted = $this->wpdb->insert(
            $table,
            [
                'token_hash'    => $tokenHash,
                'member_email'  => $memberEmail,
                'member_id'     => $memberId,
                'label'         => $label,
                'platform'      => $platform,
                'public_key'    => $publicKey,
                'push_provider' => $pushProvider,
                'push_token'    => $pushToken,
                'created_at'    => $now,
                'last_seen_at'  => $now,
            ],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%d'],
        );

        // $wpdb->insert() reports failure by returning false, and a missing
        // table is a failure like any other. Left unchecked this would
        // return a Device with id 0, the caller would mint a token for it,
        // and enrolment would answer 201 with a working-looking credential
        // for a row that does not exist. The handset stores it, 401s on its
        // very next request, and drops its member back to sign-in — with an
        // empty admin device list and nothing anywhere saying why. That
        // exact failure is documented in Reach's schema notes; silence is
        // the one failure mode enrolment cannot afford.
        if ($inserted === false || (int) $this->wpdb->insert_id <= 0) {
            throw new RuntimeException(
                'The device could not be enrolled: the write to ' . $table . ' failed. '
                . 'If the table is missing, Fellowship\Core\Schema installs it on the next load.'
            );
        }

        return new Device(
            (int) $this->wpdb->insert_id,
            $memberEmail,
            $memberId,
            $label,
            $platform,
            $publicKey,
            $pushProvider,
            $pushToken,
            $now,
            $now,
        );
    }

    public function findByTokenHash(string $tokenHash): ?Device
    {
        $table = self::tableName($this->wpdb);

        // revoked_at IS NULL is part of the lookup rather than a check the
        // caller makes afterwards: a revoked token must be
        // indistinguishable from an unknown one at every call site, and the
        // surest way to guarantee that is never to return the row.
        $row = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT {$this->columns()}
               FROM {$table}
              WHERE token_hash = %s AND revoked_at IS NULL
              LIMIT 1",
            $tokenHash,
        ), ARRAY_A);

        return is_array($row) ? $this->hydrate($row) : null;
    }

    public function findById(int $id): ?Device
    {
        $table = self::tableName($this->wpdb);
        $row = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} WHERE id = %d LIMIT 1",
            $id,
        ), ARRAY_A);

        return is_array($row) ? $this->hydrate($row) : null;
    }

    /** @return list<Device> */
    public function findByMemberEmail(string $memberEmail): array
    {
        $table = self::tableName($this->wpdb);
        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()}
               FROM {$table}
              WHERE member_email = %s AND revoked_at IS NULL
              ORDER BY id ASC",
            strtolower(trim($memberEmail)),
        ), ARRAY_A);

        return $this->hydrateAll($rows);
    }

    /** @return list<Device> */
    public function findAllLive(): array
    {
        $table = self::tableName($this->wpdb);
        $rows = $this->wpdb->get_results(
            "SELECT {$this->columns()} FROM {$table} WHERE revoked_at IS NULL ORDER BY id ASC",
            ARRAY_A,
        );

        return $this->hydrateAll($rows);
    }

    /** @return list<Device> */
    public function list(int $limit, int $offset): array
    {
        $table = self::tableName($this->wpdb);
        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
            max(1, $limit),
            max(0, $offset),
        ), ARRAY_A);

        return $this->hydrateAll($rows);
    }

    public function countAll(): int
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    public function touchLastSeen(int $id, int $now): void
    {
        $this->wpdb->update(
            self::tableName($this->wpdb),
            ['last_seen_at' => $now],
            ['id' => $id],
            ['%d'],
            ['%d'],
        );
    }

    public function updatePush(int $id, string $pushProvider, string $pushToken): void
    {
        $this->wpdb->update(
            self::tableName($this->wpdb),
            ['push_provider' => $pushProvider, 'push_token' => $pushToken],
            ['id' => $id],
            ['%s', '%s'],
            ['%d'],
        );
    }

    public function updatePublicKey(int $id, string $publicKey): bool
    {
        // A new key clears any standing key fault in the same write. The
        // fault means "I cannot open my messages"; supplying a new key is
        // the handset saying it can again, and leaving the flag set would
        // leave the admin list reporting a problem that has been fixed.
        $updated = $this->wpdb->update(
            self::tableName($this->wpdb),
            ['public_key' => $publicKey, 'key_fault_at' => null],
            ['id' => $id],
            ['%s', '%d'],
            ['%d'],
        );

        return $updated !== false;
    }

    public function markKeyFault(int $id, int $now): void
    {
        $this->wpdb->update(
            self::tableName($this->wpdb),
            ['key_fault_at' => $now],
            ['id' => $id],
            ['%d'],
            ['%d'],
        );
    }

    public function clearKeyFault(int $id): void
    {
        $this->wpdb->update(
            self::tableName($this->wpdb),
            ['key_fault_at' => null],
            ['id' => $id],
            ['%d'],
            ['%d'],
        );
    }

    public function revoke(int $id, int $now): bool
    {
        $updated = $this->wpdb->update(
            self::tableName($this->wpdb),
            ['revoked_at' => $now],
            ['id' => $id, 'revoked_at' => null],
            ['%d'],
            ['%d', '%d'],
        );

        return $updated !== false && $updated > 0;
    }

    public function revokeAllForMember(string $memberEmail, int $now): int
    {
        $table = self::tableName($this->wpdb);

        $sql = $this->wpdb->prepare(
            "UPDATE {$table} SET revoked_at = %d WHERE member_email = %s AND revoked_at IS NULL",
            $now,
            strtolower(trim($memberEmail)),
        );

        // wpdb::prepare() answers null when the query and its arguments do
        // not agree, and query() is typed to refuse that. Prepared
        // separately so the null is handled rather than becoming a
        // TypeError on a code path that only runs in production.
        $affected = is_string($sql) ? $this->wpdb->query($sql) : false;

        return is_int($affected) ? $affected : 0;
    }

    public function remove(int $id): bool
    {
        $deleted = $this->wpdb->delete(
            self::tableName($this->wpdb),
            ['id' => $id],
            ['%d'],
        );

        return $deleted !== false && $deleted > 0;
    }

    /**
     * The column list, named explicitly rather than SELECT *, so a column
     * added to the table does not silently change what hydrate() is
     * handed.
     *
     * @return literal-string
     */
    private function columns(): string
    {
        return 'id, token_hash, member_email, member_id, label, platform, public_key, '
            . 'push_provider, push_token, key_fault_at, created_at, last_seen_at, revoked_at';
    }

    /**
     * @param array<int, array<string, mixed>>|mixed $rows
     * @return list<Device>
     */
    private function hydrateAll(mixed $rows): array
    {
        if (!is_array($rows)) {
            return [];
        }

        $devices = [];
        foreach ($rows as $row) {
            if (is_array($row)) {
                $devices[] = $this->hydrate($row);
            }
        }

        return $devices;
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): Device
    {
        return new Device(
            (int) ($row['id'] ?? 0),
            (string) ($row['member_email'] ?? ''),
            (int) ($row['member_id'] ?? 0),
            (string) ($row['label'] ?? ''),
            (string) ($row['platform'] ?? ''),
            (string) ($row['public_key'] ?? ''),
            (string) ($row['push_provider'] ?? ''),
            (string) ($row['push_token'] ?? ''),
            (int) ($row['created_at'] ?? 0),
            (int) ($row['last_seen_at'] ?? 0),
            isset($row['revoked_at']) ? (int) $row['revoked_at'] : null,
            isset($row['key_fault_at']) ? (int) $row['key_fault_at'] : null,
        );
    }
}
