<?php

declare(strict_types=1);

namespace Fellowship\Push;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\Device;
use Fellowship\Logger\HasLogger;
use Fellowship\Messaging\Message;

/**
 * Pushes one message to one handset, sealed to that handset's key.
 *
 * <b>Data-only, never a notification block.</b> An FCM `notification`
 * payload is rendered by the system before the app sees it, which would
 * mean the subject and body travelling through Google in the clear and
 * landing on a lock screen. Everything here goes in `data`, the app is
 * woken to decrypt it, and the app decides what the tray says.
 *
 * What that costs on Android is that a data-only message is subject to
 * Doze and app-standby delays at normal priority. Messages are sent at
 * high priority for that reason — a member expects a message to arrive
 * when it is sent, not at the next maintenance window — and the app's
 * poll is still the reliable path behind it.
 *
 * <b>Push is the fast path, not the reliable one.</b> Every message is
 * stored before any push is attempted, and Link polls as well as
 * listening. A phone in a tunnel catches up when it surfaces, and a
 * handset whose FCM token silently rotated still gets its messages.
 * Nothing in this class should ever be the only route to a member.
 */
final class FcmTransport
{
    use HasLogger;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly FcmClient $client,
        private readonly Settings $settings,
        private readonly MessageSealer $sealer,
    ) {
    }

    /**
     * Whether this site is configured to push at all.
     *
     * Checked once by the dispatcher rather than per device, so a site
     * with no service account logs one line instead of one per handset.
     */
    public function isConfigured(): bool
    {
        return $this->account() !== null;
    }

    /**
     * Push a message to one device. False means it did not go — which is
     * survivable, because the handset will collect it on its next poll.
     */
    public function send(Device $device, Message $message): bool
    {
        $account = $this->account();
        if ($account === null) {
            return false;
        }

        if (!$device->wantsPush()) {
            return false;
        }

        $sealed = $this->sealer->seal($this->payloadFor($message), $device->publicKey);
        if ($sealed === null) {
            // A device whose key will not load cannot be sent to at all.
            // Logged with the device id and no key material, because the
            // useful next step is to look at that row in the admin list.
            self::logWarning('Message not pushed: the handset key could not be used', [
                'device'  => $device->id,
                'message' => $message->id,
            ]);
            return false;
        }

        return $this->client->send($account, [
            'token' => $device->pushToken,
            // Every value in an FCM data payload must be a string; ints
            // here would be rejected by the API rather than coerced. Both
            // fields are opaque — see MessageSealer on why nothing
            // readable travels beside them.
            'data'  => [
                'v'  => '1',
                'id' => (string) $message->id,
                'k'  => $sealed['k'],
                'p'  => $sealed['p'],
            ],
            'android' => [
                // Wakes the app from Doze. A data-only message at normal
                // priority can be held until the next maintenance window,
                // which for a message is indistinguishable from not
                // arriving.
                'priority' => 'high',
            ],
            'apns' => [
                'headers' => [
                    // 5 is the background/data priority APNs requires for a
                    // silent push; 10 would be rejected for a payload with
                    // content-available and no alert.
                    'apns-priority'  => '5',
                    'apns-push-type' => 'background',
                ],
                'payload' => [
                    'aps' => ['content-available' => 1],
                ],
            ],
        ]);
    }

    /**
     * What goes inside the envelope.
     *
     * All of it — subject, body, sender, id, timestamp. Nothing travels
     * beside the sealed blob for the handset to read first, because it
     * does not need anything first. See {@see MessageSealer}.
     *
     * @return array<string, string|int>
     */
    private function payloadFor(Message $message): array
    {
        return [
            'id'         => $message->id,
            'uuid'       => $message->uuid,
            'subject'    => $message->subject,
            'body'       => $message->body,
            'sender'     => $message->senderName,
            'created_at' => $message->createdAt,
            'reply_to'   => $message->replyToId,
        ];
    }

    private function account(): ?ServiceAccount
    {
        $json = $this->settings->getFcmServiceAccount();
        return $json === '' ? null : ServiceAccount::fromJson($json);
    }
}
