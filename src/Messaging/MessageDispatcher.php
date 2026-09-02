<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\DeviceRepository;
use Fellowship\Logger\HasLogger;
use Fellowship\Push\FcmTransport;

/**
 * Stores a message, records who it is for, and pushes it.
 *
 * <b>In that order, and the order is the design.</b> The message row and
 * its recipients are written first and the push is attempted afterwards;
 * a push that fails leaves a message the handset will collect on its next
 * poll, whereas a push attempted first would have nothing to point at.
 * This is why {@see send()} answers with the stored message rather than
 * with whether the push worked — the caller wants to know the message
 * exists, which is the part that is guaranteed.
 *
 * A send with no recipients is still stored. It happened, somebody did
 * it, and the message log showing a committee send that reached nobody
 * is how the empty committee gets noticed.
 */
final class MessageDispatcher
{
    use HasLogger;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly MessageRepository $messages,
        private readonly RecipientRepository $recipients,
        private readonly DeviceRepository $devices,
        // No RecipientResolver here on purpose: dispatch() is handed a
        // resolved list. Every caller needs that list before it can
        // dispatch — to refuse an empty send, to report a count — so
        // resolving again inside would be the same work done twice and,
        // worse, a second answer that could differ from the one the
        // caller acted on.
        private readonly FcmTransport $transport,
    ) {
    }

    /**
     * @param list<array{email: string, member_id: int}> $members Already
     *        resolved, so a caller that needed the list first — to show a
     *        confirmation, or to refuse an empty one — does not resolve
     *        it twice.
     */
    public function dispatch(
        MessageRequest $request,
        array $members,
        string $senderEmail,
        int $senderMemberId,
        string $senderName,
        int $senderDeviceId = 0,
    ): Message {
        $now = time();

        $message = $this->messages->create(
            wp_generate_uuid4(),
            $senderEmail,
            $senderMemberId,
            $senderName,
            $request->subject,
            $request->body,
            $request->audienceType,
            $request->audienceRef,
            $now,
            $request->replyToId,
            $senderDeviceId,
        );

        $this->recipients->addMany($message->id, $members, $now);

        $this->push($message, $members, $now);

        self::logInfo('Message sent', [
            'message'    => $message->id,
            'audience'   => $message->audienceType,
            'recipients' => count($members),
            'from_app'   => $senderDeviceId > 0,
        ]);

        return $message;
    }

    /**
     * Fan out to every live handset belonging to every recipient.
     *
     * @param list<array{email: string, member_id: int}> $members
     */
    private function push(Message $message, array $members, int $now): void
    {
        if ($members === []) {
            return;
        }

        // Asked once rather than per device. A site with no service
        // account should say so in one log line, not one per handset in
        // the fellowship.
        if (!$this->transport->isConfigured()) {
            self::logWarning(
                'Message stored but not pushed: no Firebase service account is configured. '
                . 'Handsets will collect it on their next poll.',
                ['message' => $message->id],
            );
            return;
        }

        foreach ($members as $member) {
            $pushed = false;

            foreach ($this->devices->findByMemberEmail($member['email']) as $device) {
                if ($this->transport->send($device, $message)) {
                    $pushed = true;
                }
            }

            // Recorded per member rather than per device, matching the
            // recipient row. "At least one of this member's handsets was
            // told" is the honest claim; see Recipient::$pushedAt on why
            // it is not called delivery.
            if ($pushed) {
                $this->recipients->markPushed($message->id, $member['email'], $now);
            }
        }
    }
}
