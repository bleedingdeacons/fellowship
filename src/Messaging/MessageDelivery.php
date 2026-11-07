<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Firebase\FirebaseUnavailable;

/**
 * Where a message sealed in WordPress goes.
 *
 * `$audience` holds any of `everyone`, `memberIds`, `committees` and `gsrs`, with
 * `senderMemberId`. Both calls take the same one, because the far side works the
 * audience out again and refuses a set of envelopes that doesn't match it.
 */
interface MessageDelivery
{
    /**
     * Who this reaches, and the id to seal inside the message.
     *
     * @param array<string, mixed> $audience
     *
     * @return array{id: int, members: int, devices: list<array{deviceId: string, publicKey: string}>}
     *
     * @throws FirebaseUnavailable When it couldn't be asked, or refused.
     */
    public function resolve(array $audience): array;

    /**
     * @param array<string, mixed>                              $audience
     * @param list<array{deviceId: string, k: string, p: string}> $envelopes
     *
     * @return int How many members it reached.
     *
     * @throws FirebaseUnavailable When it couldn't be asked, or refused.
     */
    public function deliver(array $audience, int $id, array $envelopes): int;
}
