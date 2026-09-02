<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use RuntimeException;
use wpdb;

use function dbDelta;

/**
 * Messages, in a table of their own.
 *
 * The body column is `TEXT` rather than `VARCHAR(2000)`: the cap in
 * {@see MessageRequest} is measured in bytes for FCM's benefit, and a
 * VARCHAR whose length is counted in characters would disagree with it on
 * any message containing an accent.
 */
final class WpdbMessageRepository implements MessageRepository
{
    public const TABLE_SUFFIX = 'fellowship_messages';

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

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            uuid CHAR(36) NOT NULL,
            sender_email VARCHAR(254) NOT NULL DEFAULT '',
            sender_member_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            sender_name VARCHAR(200) NOT NULL DEFAULT '',
            sender_device_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            subject VARCHAR(255) NOT NULL DEFAULT '',
            body TEXT NULL,
            audience_type VARCHAR(16) NOT NULL DEFAULT '',
            audience_ref VARCHAR(200) NOT NULL DEFAULT '',
            reply_to_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            created_at BIGINT UNSIGNED NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY uuid (uuid),
            KEY created_at (created_at),
            KEY reply_to_id (reply_to_id)
        ) {$charset};";

        dbDelta($sql);
    }

    public function create(
        string $uuid,
        string $senderEmail,
        int $senderMemberId,
        string $senderName,
        string $subject,
        string $body,
        string $audienceType,
        string $audienceRef,
        int $createdAt,
        int $replyToId,
        int $senderDeviceId,
    ): Message {
        $table = self::tableName($this->wpdb);

        $inserted = $this->wpdb->insert(
            $table,
            [
                'uuid'             => $uuid,
                'sender_email'     => $senderEmail,
                'sender_member_id' => $senderMemberId,
                'sender_name'      => $senderName,
                'sender_device_id' => $senderDeviceId,
                'subject'          => $subject,
                'body'             => $body,
                'audience_type'    => $audienceType,
                'audience_ref'     => $audienceRef,
                'reply_to_id'      => $replyToId,
                'created_at'       => $createdAt,
            ],
            ['%s', '%s', '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%d'],
        );

        // Same reasoning as device enrolment: a failed insert that
        // returns quietly would have the dispatcher fan out push
        // notifications pointing at a message id of 0, which every
        // handset would then fail to fetch. Fail where the fault is.
        if ($inserted === false || (int) $this->wpdb->insert_id <= 0) {
            throw new RuntimeException(
                'The message could not be stored: the write to ' . $table . ' failed. '
                . 'If the table is missing, Fellowship\Core\Schema installs it on the next load.'
            );
        }

        return new Message(
            (int) $this->wpdb->insert_id,
            $uuid,
            $senderEmail,
            $senderMemberId,
            $senderName,
            $subject,
            $body,
            $audienceType,
            $audienceRef,
            $createdAt,
            $replyToId,
            $senderDeviceId,
        );
    }

    public function findById(int $id): ?Message
    {
        $table = self::tableName($this->wpdb);
        $row = $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} WHERE id = %d LIMIT 1",
            $id,
        ), ARRAY_A);

        return is_array($row) ? $this->hydrate($row) : null;
    }

    /**
     * @param list<int> $ids
     * @return array<int, Message>
     */
    public function findByIds(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn(int $id): bool => $id > 0)));
        if ($ids === []) {
            return [];
        }

        $table = self::tableName($this->wpdb);

        // The placeholder list is built from a count, not from the values,
        // so the query string stays a literal as far as wpdb::prepare is
        // concerned and every id still goes through %d.
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));

        /** @var array<int, array<string, mixed>>|null $rows */
        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} WHERE id IN ({$placeholders})",
            ...$ids,
        ), ARRAY_A);

        $messages = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            if (is_array($row)) {
                $message = $this->hydrate($row);
                $messages[$message->id] = $message;
            }
        }

        return $messages;
    }

    /** @return list<Message> */
    public function list(int $limit, int $offset): array
    {
        $table = self::tableName($this->wpdb);
        $rows = $this->wpdb->get_results($this->wpdb->prepare(
            "SELECT {$this->columns()} FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
            max(1, $limit),
            max(0, $offset),
        ), ARRAY_A);

        $messages = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            if (is_array($row)) {
                $messages[] = $this->hydrate($row);
            }
        }

        return $messages;
    }

    public function countAll(): int
    {
        $table = self::tableName($this->wpdb);
        return (int) $this->wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    public function purgeBefore(int $before): int
    {
        $table = self::tableName($this->wpdb);
        $sql = $this->wpdb->prepare(
            "DELETE FROM {$table} WHERE created_at < %d",
            $before,
        );

        // wpdb::prepare() answers null when the query and its arguments
        // do not agree, and query() is typed to refuse that. Prepared
        // separately so the null is handled rather than becoming a
        // TypeError on a code path that only runs in production.
        $deleted = is_string($sql) ? $this->wpdb->query($sql) : false;

        return is_int($deleted) ? $deleted : 0;
    }

    public function delete(int $id): bool
    {
        $deleted = $this->wpdb->delete(self::tableName($this->wpdb), ['id' => $id], ['%d']);
        return $deleted !== false && $deleted > 0;
    }

    /** @return literal-string */
    private function columns(): string
    {
        return 'id, uuid, sender_email, sender_member_id, sender_name, sender_device_id, '
            . 'subject, body, audience_type, audience_ref, reply_to_id, created_at';
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): Message
    {
        return new Message(
            (int) ($row['id'] ?? 0),
            (string) ($row['uuid'] ?? ''),
            (string) ($row['sender_email'] ?? ''),
            (int) ($row['sender_member_id'] ?? 0),
            (string) ($row['sender_name'] ?? ''),
            (string) ($row['subject'] ?? ''),
            (string) ($row['body'] ?? ''),
            (string) ($row['audience_type'] ?? ''),
            (string) ($row['audience_ref'] ?? ''),
            (int) ($row['created_at'] ?? 0),
            (int) ($row['reply_to_id'] ?? 0),
            (int) ($row['sender_device_id'] ?? 0),
        );
    }
}
