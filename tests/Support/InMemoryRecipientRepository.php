<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Messaging\Recipient;
use Fellowship\Messaging\RecipientRepository;

/**
 * Recipient rows, in memory.
 *
 * <b>markRead is scoped to the member on purpose</b>, exactly as the SQL
 * is. A double that ignored the address would let a controller test pass
 * while the real thing let any handset mark any message read.
 */
final class InMemoryRecipientRepository implements RecipientRepository
{
    /** @var list<Recipient> */
    public array $rows = [];

    private int $nextId = 1;

    public function addMany(int $messageId, array $members, int $now): int
    {
        $added = 0;

        foreach ($members as $member) {
            // The contract is array{email: string, member_id: int}.
            $email = is_array($member) ? (string) ($member['email'] ?? '') : (string) $member;
            $id = is_array($member) ? (int) ($member['member_id'] ?? 0) : 0;

            if ($email === '') {
                continue;
            }

            $this->rows[] = new Recipient($this->nextId++, $messageId, strtolower($email), $id, $now);
            $added++;
        }

        return $added;
    }

    public function forMember(string $memberEmail, int $sinceMessageId, int $limit): array
    {
        $email = strtolower(trim($memberEmail));

        $matching = array_filter(
            $this->rows,
            static fn(Recipient $r): bool => $r->memberEmail === $email && $r->messageId > $sinceMessageId,
        );

        usort($matching, static fn(Recipient $a, Recipient $b): int => $b->messageId <=> $a->messageId);

        return array_slice(array_values($matching), 0, max(1, $limit));
    }

    public function countUnread(string $memberEmail): int
    {
        $email = strtolower(trim($memberEmail));

        return count(array_filter(
            $this->rows,
            static fn(Recipient $r): bool => $r->memberEmail === $email && $r->readAt === null,
        ));
    }

    public function markRead(int $messageId, string $memberEmail, int $now): bool
    {
        $email = strtolower(trim($memberEmail));

        foreach ($this->rows as $index => $row) {
            if ($row->messageId !== $messageId || $row->memberEmail !== $email || $row->readAt !== null) {
                continue;
            }

            $this->rows[$index] = new Recipient(
                $row->id,
                $row->messageId,
                $row->memberEmail,
                $row->memberId,
                $row->createdAt,
                $now,
                $row->pushedAt,
            );

            return true;
        }

        return false;
    }

    public function markPushed(int $messageId, string $memberEmail, int $now): void
    {
        $email = strtolower(trim($memberEmail));

        foreach ($this->rows as $index => $row) {
            if ($row->messageId === $messageId && $row->memberEmail === $email) {
                $this->rows[$index] = new Recipient(
                    $row->id,
                    $row->messageId,
                    $row->memberEmail,
                    $row->memberId,
                    $row->createdAt,
                    $row->readAt,
                    $now,
                );
            }
        }
    }

    public function forMessage(int $messageId): array
    {
        return array_values(array_filter(
            $this->rows,
            static fn(Recipient $r): bool => $r->messageId === $messageId,
        ));
    }

    public function countForMessage(int $messageId): int
    {
        return count($this->forMessage($messageId));
    }

    public function countReadForMessage(int $messageId): int
    {
        return count(array_filter(
            $this->forMessage($messageId),
            static fn(Recipient $r): bool => $r->readAt !== null,
        ));
    }

    public function purgeForMessagesBefore(int $before): int
    {
        return 0;
    }

    public function deleteForMessage(int $messageId): int
    {
        $before = count($this->rows);

        $this->rows = array_values(array_filter(
            $this->rows,
            static fn(Recipient $r): bool => $r->messageId !== $messageId,
        ));

        return $before - count($this->rows);
    }

    public function deleteForMember(string $memberEmail): int
    {
        $email = strtolower(trim($memberEmail));
        $before = count($this->rows);

        $this->rows = array_values(array_filter(
            $this->rows,
            static fn(Recipient $r): bool => $r->memberEmail !== $email,
        ));

        return $before - count($this->rows);
    }
}
