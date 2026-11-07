<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Messaging\LoggedMessage;
use Fellowship\Messaging\MessageLog;

/** The message log, read from Firestore. Who received a message isn't fetched for it. */
final class FirestoreMessageLog implements MessageLog
{
    private const FIELDS = ['senderMemberId', 'audience', 'recipientCount', 'receivedCount', 'readCount', 'createdAt'];

    public function __construct(private readonly FirestoreClient $firestore)
    {
    }

    public function page(int $limit, int $offset): array
    {
        return array_map(
            static fn(array $row): LoggedMessage => self::message($row['id'], $row['fields']),
            $this->firestore->query('messages', self::FIELDS, 'createdAt', $limit, $offset),
        );
    }

    /** @param array<string, mixed> $fields */
    private static function message(string $id, array $fields): LoggedMessage
    {
        return new LoggedMessage(
            (int) $id,
            self::number($fields, 'senderMemberId'),
            is_string($fields['audience'] ?? null) ? $fields['audience'] : '',
            self::number($fields, 'recipientCount'),
            self::number($fields, 'receivedCount'),
            self::number($fields, 'readCount'),
            FirestoreClient::epoch($fields['createdAt'] ?? null),
        );
    }

    /** @param array<string, mixed> $fields */
    private static function number(array $fields, string $name): int
    {
        return is_int($fields[$name] ?? null) ? $fields[$name] : 0;
    }
}
