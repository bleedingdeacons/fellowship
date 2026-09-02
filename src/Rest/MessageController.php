<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\Device;
use Fellowship\Logger\HasLogger;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Messaging\RecipientResolver;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Unity\Members\Interfaces\MemberRepository;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;

/**
 * Reading and sending messages from a handset.
 *
 * <b>Everything a handset reads is sealed, including the poll.</b> It
 * would be easy to seal the push — where the payload crosses Google —
 * and return plain JSON on the polling route, which is TLS-protected
 * anyway. That would be a mistake: the same message would then exist in
 * two forms, and the app would need two code paths to read one inbox.
 * One envelope, one reader, and the difference between arriving by push
 * and arriving by poll stops being something the app has to care about.
 *
 * <b>The app addresses by member id, never by email.</b> The directory
 * hands out opaque ids and this resolves them; a handset therefore never
 * holds the intergroup's address list, and a message cannot be addressed
 * to somebody who is not a member by inventing an address.
 */
final class MessageController
{
    use HasLogger;
    use RequiresSecureTransport;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public const NAMESPACE = 'fellowship/v1';

    /** Messages returned by one poll. */
    private const PAGE_DEFAULT = 50;
    private const PAGE_MAX = 200;

    /** Sends allowed from one device per window, and the window. */
    private const SEND_MAX = 20;
    private const SEND_WINDOW = 900;

    public function __construct(
        private readonly CurrentDevice $currentDevice,
        private readonly MessageRepository $messages,
        private readonly RecipientRepository $recipients,
        private readonly MessageDispatcher $dispatcher,
        private readonly RecipientResolver $resolver,
        private readonly MessageSealer $sealer,
        private readonly MemberRepository $members,
        private readonly Settings $settings,
        private readonly RateLimiter $rateLimiter,
        private readonly AuditLogger $auditLogger,
    ) {
    }

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/messages', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'inbox'],
                'permission_callback' => '__return_true',
                'args'                => [
                    'since' => ['type' => 'integer', 'required' => false, 'default' => 0],
                    'limit' => ['type' => 'integer', 'required' => false, 'default' => self::PAGE_DEFAULT],
                ],
            ],
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [$this, 'send'],
                'permission_callback' => '__return_true',
                'args'                => [
                    'subject'    => ['type' => 'string', 'required' => true],
                    'body'       => ['type' => 'string', 'required' => true],
                    'member_ids' => ['type' => 'array', 'required' => false, 'items' => ['type' => 'integer']],
                    'committee'  => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
                    'reply_to'   => ['type' => 'integer', 'required' => false, 'default' => 0],
                ],
            ],
        ]);

        register_rest_route(self::NAMESPACE, '/messages/(?P<id>\d+)/read', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'markRead'],
            'permission_callback' => '__return_true',
            'args'                => [
                'id' => ['type' => 'integer', 'required' => true],
            ],
        ]);
    }

    /**
     * Everything addressed to this member since the id the handset
     * already holds.
     *
     * <b>Ordered newest first but paged by id, which is deliberate.</b> A
     * handset that has been offline for a month asks for everything after
     * its last id and walks forward; one that is up to date asks for
     * everything after the newest it has and usually gets nothing. Paging
     * by timestamp would be ambiguous for two messages in the same
     * second, and this is the one query that runs every few minutes on
     * every handset in the fellowship.
     */
    public function inbox(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $limit = min(self::PAGE_MAX, max(1, (int) $request->get_param('limit')));
        $since = max(0, (int) $request->get_param('since'));

        $rows = $this->recipients->forMember($device->memberEmail, $since, $limit);
        if ($rows === []) {
            return new WP_REST_Response(['messages' => [], 'unread' => 0], 200);
        }

        $messages = $this->messages->findByIds(array_map(
            static fn($recipient): int => $recipient->messageId,
            $rows,
        ));

        $sealed = [];
        $unreadable = 0;

        foreach ($rows as $recipient) {
            $message = $messages[$recipient->messageId] ?? null;
            if ($message === null) {
                // A recipient row whose message has been purged. Skipped
                // rather than reported: the sweep deletes recipients
                // first, so this is a narrow race rather than a fault,
                // and the handset has nothing to do about it.
                continue;
            }

            $envelope = $this->sealer->seal($this->payloadFor($message, $recipient->readAt), $device->publicKey);
            if ($envelope === null) {
                $unreadable++;
                continue;
            }

            $sealed[] = [
                'id' => $message->id,
                'k'  => $envelope['k'],
                'p'  => $envelope['p'],
            ];
        }

        if ($unreadable > 0) {
            // The handset's stored key stopped working. It will see a
            // short inbox and no explanation, so say it here where
            // somebody can act on it.
            self::logWarning('Some messages could not be sealed for a handset', [
                'device' => $device->id,
                'count'  => $unreadable,
            ]);
        }

        return new WP_REST_Response([
            'messages' => $sealed,
            'unread'   => $this->recipients->countUnread($device->memberEmail),
        ], 200);
    }

    /**
     * Send from a handset.
     */
    public function send(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        if ($this->rateLimiter->overLimit('send_' . $device->id, self::SEND_MAX, self::SEND_WINDOW)) {
            return new WP_Error(
                'fellowship_rate_limited',
                'Too many messages sent from this device. Please wait a few minutes.',
                ['status' => 429],
            );
        }

        $member = $this->currentDevice->memberFor($device);
        if ($member === null) {
            return new WP_Error('fellowship_unauthenticated', 'This device is not signed in.', ['status' => 401]);
        }

        $committee = (string) $request->get_param('committee');
        if ($committee !== '' && !$this->settings->allowsCommitteeSendFromApp()) {
            return new WP_Error(
                'fellowship_committee_send_disabled',
                'Sending to a committee from the app is not enabled on this site.',
                ['status' => 403],
            );
        }

        $replyTo = max(0, (int) $request->get_param('reply_to'));
        if ($replyTo > 0 && !$this->mayReplyTo($replyTo, $device)) {
            // Refused as "not found" rather than "not yours": answering
            // differently would let a handset walk the id space to learn
            // which messages exist.
            return new WP_Error('fellowship_no_such_message', 'No such message.', ['status' => 404]);
        }

        $built = MessageRequest::fromArray([
            'subject'       => $request->get_param('subject'),
            'body'          => $request->get_param('body'),
            'committee'     => $committee,
            'member_emails' => $this->emailsForIds($request->get_param('member_ids')),
            'reply_to'      => $replyTo,
        ]);

        if ($built instanceof WP_Error) {
            return $built;
        }

        // A handset may not address the whole fellowship. That is a
        // broadcast, it belongs to whoever holds the send capability in
        // WordPress, and the app has no undo.
        if ($built->audienceType === Message::AUDIENCE_ALL) {
            return new WP_Error(
                'fellowship_no_audience',
                'Choose who this message is for.',
                ['status' => 400],
            );
        }

        $senderEmail = strtolower(trim($member->getPersonalEmail()));
        $recipients = $this->resolver->resolve($built, $senderEmail);

        if ($recipients === []) {
            return new WP_Error(
                'fellowship_no_recipients',
                'That message would not reach anybody.',
                ['status' => 400],
            );
        }

        try {
            $message = $this->dispatcher->dispatch(
                $built,
                $recipients,
                $senderEmail,
                $member->getId(),
                $member->getAnonymousName(),
                $device->id,
            );
        } catch (\RuntimeException $e) {
            self::logError('Message from a handset could not be stored', [
                'device' => $device->id,
                'error'  => $e->getMessage(),
            ]);

            return new WP_Error('fellowship_send_failed', 'The message could not be sent.', ['status' => 500]);
        }

        // Recorded against the sender, and holding no message text. What
        // was said is already in a table Scrutiny does not need a second
        // copy of; what the audit trail is for is who reached whom.
        $this->auditLogger->log(
            AuditLogger::ACTION_MESSAGE,
            AuditLogger::ENTITY_MEMBER,
            $member->getId(),
            'message',
            'Message sent from Link;message:' . $message->id
                . ';audience:' . $message->audienceType
                . ($message->audienceRef !== '' ? ';ref:' . $message->audienceRef : '')
                . ';recipients:' . count($recipients)
                . ';device:' . $device->id,
        );

        return new WP_REST_Response([
            'id'         => $message->id,
            'uuid'       => $message->uuid,
            'recipients' => count($recipients),
            'created_at' => $message->createdAt,
        ], 201);
    }

    public function markRead(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $messageId = (int) $request->get_param('id');

        if (!$this->recipients->markRead($messageId, $device->memberEmail, time())) {
            return new WP_Error('fellowship_no_such_message', 'No such message.', ['status' => 404]);
        }

        return new WP_REST_Response([
            'ok'     => true,
            'unread' => $this->recipients->countUnread($device->memberEmail),
        ], 200);
    }

    /**
     * A member may reply to a message they received, or to one they sent.
     *
     * The second half matters for a conversation: without it, replying to
     * your own message in a thread you started would be refused.
     */
    private function mayReplyTo(int $messageId, Device $device): bool
    {
        $message = $this->messages->findById($messageId);
        if ($message === null) {
            return false;
        }

        if (strtolower($message->senderEmail) === strtolower($device->memberEmail)) {
            return true;
        }

        foreach ($this->recipients->forMessage($messageId) as $recipient) {
            if (strtolower($recipient->memberEmail) === strtolower($device->memberEmail)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Turn the opaque member ids the app holds into addresses.
     *
     * An id that does not resolve is dropped rather than refused: a
     * directory the handset cached last week can name somebody who has
     * since been removed, and failing the whole send for one stale entry
     * would be a poor answer to an ordinary situation. The send is still
     * refused if nothing resolves, by the empty-recipients check.
     *
     * @return list<string>
     */
    private function emailsForIds(mixed $ids): array
    {
        if (!is_array($ids)) {
            return [];
        }

        $emails = [];
        foreach ($ids as $id) {
            $member = $this->members->findById((int) $id);
            if ($member === null) {
                continue;
            }

            $email = strtolower(trim($member->getPersonalEmail()));
            if ($email !== '') {
                $emails[] = $email;
            }
        }

        return $emails;
    }

    /**
     * What goes inside the envelope on the polling route.
     *
     * The same shape the push carries, plus the read flag — a handset
     * that has been offline needs to know which of these it has already
     * dealt with elsewhere.
     *
     * @return array<string, string|int>
     */
    private function payloadFor(Message $message, ?int $readAt): array
    {
        return [
            'id'         => $message->id,
            'uuid'       => $message->uuid,
            'subject'    => $message->subject,
            'body'       => $message->body,
            'sender'     => $message->senderName,
            'created_at' => $message->createdAt,
            'reply_to'   => $message->replyToId,
            'read_at'    => $readAt ?? 0,
        ];
    }

    /** @return Device|WP_Error */
    private function authenticate(WP_REST_Request $request): Device|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        $device = $this->currentDevice->fromRequest($request);

        return $device ?? new WP_Error(
            'fellowship_unauthenticated',
            'This device is not signed in.',
            ['status' => 401],
        );
    }
}
