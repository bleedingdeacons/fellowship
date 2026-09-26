<?php

declare(strict_types=1);

namespace Fellowship\Push;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * What became of one push to one handset.
 *
 * <b>Three answers, not two, because one failure is about the device
 * row rather than the message.</b> Everything that can go wrong with a
 * push is survivable — the message is stored and the poll collects it —
 * but most of it is also transient: a rate limit, a timeout, a bad hour
 * at Google. {@see self::Unregistered} is not. It is FCM saying the
 * token no longer belongs to any installation, and it will say so for
 * every message sent to it from now on. Until 2026-09-26 that was folded
 * into a plain false, so the dead token stayed on the row, the admin
 * list showed the handset as push-capable, and every message after the
 * rotation failed identically while nothing looked wrong from either end.
 */
enum PushOutcome
{
    /** FCM accepted it. Not delivery — see Recipient::$pushedAt. */
    case Sent;

    /** It did not go this time. The handset will collect it on its next poll. */
    case Failed;

    /**
     * FCM no longer recognises the token: the app was reinstalled, its
     * data cleared, or the token rotated without the handset reporting
     * it. The caller should stop sending to it.
     */
    case Unregistered;
}
