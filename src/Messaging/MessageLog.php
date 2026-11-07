<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Firebase\FirebaseUnavailable;

/** What has been sent, for the Messages screen. */
interface MessageLog
{
    /**
     * Newest first.
     *
     * @return list<LoggedMessage>
     *
     * @throws FirebaseUnavailable When it couldn't be asked, which a screen must not
     *                             mistake for nothing having been sent.
     */
    public function page(int $limit, int $offset): array;
}
