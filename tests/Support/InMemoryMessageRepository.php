<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRepository;

/**
 * Messages, in memory.
 */
class InMemoryMessageRepository implements MessageRepository
{
    /** @var array<int, Message> */
    public array $rows = [];

    private int $nextId = 1;

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
        $message = new Message(
            $this->nextId++,
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

        $this->rows[$message->id] = $message;

        return $message;
    }

    public function findById(int $id): ?Message
    {
        return $this->rows[$id] ?? null;
    }

    public function findByIds(array $ids): array
    {
        $found = [];

        foreach ($ids as $id) {
            if (isset($this->rows[$id])) {
                $found[$id] = $this->rows[$id];
            }
        }

        return $found;
    }

    public function list(int $limit, int $offset): array
    {
        return array_slice(array_reverse(array_values($this->rows)), $offset, $limit);
    }

    public function countAll(): int
    {
        return count($this->rows);
    }

    public function purgeBefore(int $before): int
    {
        $removed = 0;

        foreach ($this->rows as $id => $message) {
            if ($message->createdAt < $before) {
                unset($this->rows[$id]);
                $removed++;
            }
        }

        return $removed;
    }

    public function delete(int $id): bool
    {
        if (!isset($this->rows[$id])) {
            return false;
        }

        unset($this->rows[$id]);

        return true;
    }
}
