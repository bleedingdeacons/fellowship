<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Storage for messages themselves. Who each one reached is
 * {@see RecipientRepository}.
 */
interface MessageRepository
{
    /** @throws \RuntimeException When the row could not be written. */
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
    ): Message;

    public function findById(int $id): ?Message;

    /**
     * @param list<int> $ids
     * @return array<int, Message> Keyed by id, so a caller joining
     *         recipient rows to messages does not have to search.
     */
    public function findByIds(array $ids): array;

    /**
     * One page of the message log, newest first.
     *
     * @return list<Message>
     */
    public function list(int $limit, int $offset): array;

    public function countAll(): int;

    /**
     * Delete messages created before $before, and return how many went.
     *
     * Recipient rows are deleted first by the caller — see
     * {@see \Fellowship\Plugin} — because they are found by joining to
     * these, and a recipient row pointing at a message that no longer
     * exists is orphaned personal data.
     */
    public function purgeBefore(int $before): int;

    public function delete(int $id): bool;
}
