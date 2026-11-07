<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Messaging\LoggedMessage;
use Fellowship\Messaging\MessageLog;

/** The log in a list. Set {@see $down} and it fails as Firebase being out would. */
final class InMemoryMessageLog implements MessageLog
{
    /** @var list<LoggedMessage> */
    public array $rows = [];

    public bool $down = false;

    public function add(
        int $senderMemberId = 7,
        string $audience = LoggedMessage::AUDIENCE_MEMBERS,
        int $recipients = 1,
        int $received = 0,
        int $read = 0,
        int $createdAt = 1788000000,
    ): void {
        $this->rows[] = new LoggedMessage(
            count($this->rows) + 1,
            $senderMemberId,
            $audience,
            $recipients,
            $received,
            $read,
            $createdAt,
        );
    }

    public function page(int $limit, int $offset): array
    {
        if ($this->down) {
            throw new FirebaseUnavailable('Firestore could not be reached.');
        }

        return array_slice($this->rows, $offset, $limit);
    }
}
