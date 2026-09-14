<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Who each message reached, and what became of it.
 */
interface RecipientRepository
{
    /**
     * Record that a message was addressed to these members.
     *
     * @param list<array{email: string, member_id: int}> $members
     * @return int How many rows were written.
     */
    public function addMany(int $messageId, array $members, int $now): int;

    /**
     * A member's messages, newest first, optionally only those newer
     * than an id the handset already holds.
     *
     * @return list<Recipient>
     */
    public function forMember(string $memberEmail, int $sinceMessageId, int $limit): array;

    public function countUnread(string $memberEmail): int;

    /**
     * Mark one member's copy read. Returns false when the message was
     * never addressed to them, which a caller should treat as a 404
     * rather than a success — otherwise a handset could probe for the
     * existence of messages it was not sent.
     */
    public function markRead(int $messageId, string $memberEmail, int $now): bool;

    public function markPushed(int $messageId, string $memberEmail, int $now): void;

    /**
     * Record that one of the member's handsets has opened these messages.
     *
     * Scoped to the member exactly as {@see markRead()} is, so an id that
     * was never addressed to them changes nothing. A row already marked
     * keeps its first time.
     *
     * @param list<int> $messageIds
     * @return int How many rows were newly marked.
     */
    public function markReceived(array $messageIds, string $memberEmail, int $now): int;

    /**
     * How far each of these messages has got: recipients, how many of them
     * have received it, and how many have read it.
     *
     * A read counts as received. A message with no recipient rows is
     * absent from the answer rather than present with zeroes.
     *
     * @param list<int> $messageIds
     * @return array<int, array{recipients: int, received: int, read: int}> Keyed by message id.
     */
    public function receiptsFor(array $messageIds): array;

    /** @return list<Recipient> */
    public function forMessage(int $messageId): array;

    public function countForMessage(int $messageId): int;

    public function countReadForMessage(int $messageId): int;

    /** Delete every recipient row for messages created before $before. */
    public function purgeForMessagesBefore(int $before): int;

    public function deleteForMessage(int $messageId): int;

    /** Delete every row for one member — GDPR erasure. */
    public function deleteForMember(string $memberEmail): int;
}
