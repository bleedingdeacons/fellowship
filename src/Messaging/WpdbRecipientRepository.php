<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use wpdb;

use function dbDelta;

/**
 * Recipient rows.
 *
 * The unique key on (message_id, member_email) is what makes a resend
 * idempotent: a committee that gained a member between two attempts adds
 * one row, and a member already on the list does not get a duplicate.
 */
final class WpdbRecipientRepository implements RecipientRepository
{
    public const TABLE_SUFFIX = 'fellowship_recipients';

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

        // member_email is indexed at 191 characters rather than its full
        // 254: a utf8mb4 index entry is four bytes per character and
        // InnoDB's limit is 3072 bytes, which a composite key with
        // message_id would otherwise clear only by luck. No real address
        // is anywhere near 191 characters, so the prefix is exact in
        // practice.
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            message_id BIGINT UNSIGNED NOT NULL,
            member_email VARCHAR(254) NOT NULL,
            member_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            created_at BIGINT UNSIGNED NOT NULL,
            read_at BIGINT UNSIGNED NULL,
            pushed_at BIGINT UNSIGNED NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY message_member (message_id, member_email(191)),
            KEY member_email (member_email(191)),
            KEY read_at (read_at)
        ) {$charset};";

        dbDelta($sql);
    }

    /**
     * @param list<array{email: string, member_id: int}> $members
     */
    public function addMany(int $messageId, array $members, int $now): int
    {
        $written = 0;

        foreach ($members as $member) {
            $email = strtolower(trim($member['email'] ?? ''));
            if ($email === '') {
                continue;
            }

            // INSERT IGNORE rather than a check-then-insert: two sends
            // racing on the same committee would both see "not there"
            // and both write. The unique key is the arbiter, and letting
            // it be one costs a duplicate-key warning instead of a
            // duplicate row.
            $table = self::tableName($this->wpdb);
            $sql = $this->wpdb->prepare(
                "INSERT IGNORE INTO {$table}
                    (message_id, member_email, member_id, created_at)
                 VALUES (%d, %s, %d, %d)",
                $messageId,
                $email,
                (int) ($member['member_id'] ?? 0),
                $now,
            );

            // wpdb::prepare() answers null when the query and its arguments
            // do not agree, and query() is typed to refuse that. Prepared
            // separately so the null is handled rather than becoming a
            // TypeError on a code path that only runs in production.
            $result = is_string($sql) ? $this->wpdb->query($sql) : false;

            if (is_int($result) && $result > 0) {
                $written++;
            }
        }

        return $written;
    }

    /** @return list<Recipient> */
    public function forMember(string $memberEmail, int $sinceMessageId, int $limit): array
    {
        $table = self::tableName($this->wpdb);
        $email = strtolower(trim($memberEmail));

        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()}
               FROM {$table}
              WHERE member_email = %s AND message_id > %d
              ORDER BY message_id DESC
              LIMIT %d",
            $email,
            max(0, $sinceMessageId),
            max(1, $limit),
        ), ARRAY_A);

        return $this->hydrateAll($rows);
    }

    public function countUnread(string $memberEmail): int
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE member_email = %s AND read_at IS NULL",
            strtolower(trim($memberEmail)),
        ));
    }

    public function markRead(int $messageId, string $memberEmail, int $now): bool
    {
        $table = self::tableName($this->wpdb);

        // The WHERE clause is the authorisation. A handset can only mark
        // read what was actually addressed to its member, so a request
        // naming somebody else's message affects nothing and answers the
        // same as a message that does not exist.
        $sql = $this->wpdb->prepare(
            "UPDATE {$table}
                SET read_at = %d
              WHERE message_id = %d AND member_email = %s AND read_at IS NULL",
            $now,
            $messageId,
            strtolower(trim($memberEmail)),
        );

        // wpdb::prepare() answers null when the query and its arguments
        // do not agree, and query() is typed to refuse that. Prepared
        // separately so the null is handled rather than becoming a
        // TypeError on a code path that only runs in production.
        $updated = is_string($sql) ? $this->wpdb->query($sql) : false;

        if (is_int($updated) && $updated > 0) {
            return true;
        }

        // Already read is still "yes, this is yours". Answering false
        // would make a handset retrying a marked-read call look like one
        // probing for somebody else's message.
        return $this->exists($messageId, $memberEmail);
    }

    public function markPushed(int $messageId, string $memberEmail, int $now): void
    {
        $this->wpdb->update(
            self::tableName($this->wpdb),
            ['pushed_at' => $now],
            ['message_id' => $messageId, 'member_email' => strtolower(trim($memberEmail))],
            ['%d'],
            ['%d', '%s'],
        );
    }

    /** @return list<Recipient> */
    public function forMessage(int $messageId): array
    {
        $table = self::tableName($this->wpdb);
        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} WHERE message_id = %d ORDER BY id ASC",
            $messageId,
        ), ARRAY_A);

        return $this->hydrateAll($rows);
    }

    public function countForMessage(int $messageId): int
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE message_id = %d",
            $messageId,
        ));
    }

    public function countReadForMessage(int $messageId): int
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE message_id = %d AND read_at IS NOT NULL",
            $messageId,
        ));
    }

    public function purgeForMessagesBefore(int $before): int
    {
        $recipients = self::tableName($this->wpdb);
        $messages   = WpdbMessageRepository::tableName($this->wpdb);

        $sql = $this->wpdb->prepare(
            "DELETE r FROM {$recipients} r
               INNER JOIN {$messages} m ON m.id = r.message_id
              WHERE m.created_at < %d",
            $before,
        );

        // wpdb::prepare() answers null when the query and its arguments
        // do not agree, and query() is typed to refuse that. Prepared
        // separately so the null is handled rather than becoming a
        // TypeError on a code path that only runs in production.
        $deleted = is_string($sql) ? $this->wpdb->query($sql) : false;

        return is_int($deleted) ? $deleted : 0;
    }

    public function deleteForMessage(int $messageId): int
    {
        $deleted = $this->wpdb->delete(
            self::tableName($this->wpdb),
            ['message_id' => $messageId],
            ['%d'],
        );

        return is_int($deleted) ? $deleted : 0;
    }

    public function deleteForMember(string $memberEmail): int
    {
        $deleted = $this->wpdb->delete(
            self::tableName($this->wpdb),
            ['member_email' => strtolower(trim($memberEmail))],
            ['%s'],
        );

        return is_int($deleted) ? $deleted : 0;
    }

    private function exists(int $messageId, string $memberEmail): bool
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE message_id = %d AND member_email = %s",
            $messageId,
            strtolower(trim($memberEmail)),
        )) > 0;
    }

    /** @return literal-string */
    private function columns(): string
    {
        return 'id, message_id, member_email, member_id, created_at, read_at, pushed_at';
    }

    /**
     * @param array<int, array<string, mixed>>|mixed $rows
     * @return list<Recipient>
     */
    private function hydrateAll(mixed $rows): array
    {
        if (!is_array($rows)) {
            return [];
        }

        $recipients = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $recipients[] = new Recipient(
                (int) ($row['id'] ?? 0),
                (int) ($row['message_id'] ?? 0),
                (string) ($row['member_email'] ?? ''),
                (int) ($row['member_id'] ?? 0),
                (int) ($row['created_at'] ?? 0),
                isset($row['read_at']) ? (int) $row['read_at'] : null,
                isset($row['pushed_at']) ? (int) $row['pushed_at'] : null,
            );
        }

        return $recipients;
    }
}
