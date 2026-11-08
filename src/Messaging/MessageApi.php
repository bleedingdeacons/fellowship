<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Crypto\MessageSealer;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Logger\HasLogger;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Throwable;
use Unity\Members\Interfaces\Member;
use WP_Error;

use function add_action;

/**
 * The supported way for other plugins — and Fellowship's own admin
 * screens — to send a message.
 *
 * Two forms, the same code behind both: the function
 * `fellowship_send_message()` declared in the plugin bootstrap, and the
 * action `fellowship/send_message` registered here for callers that
 * would rather not depend on a function existing.
 *
 * <b>A send from here has no member behind it unless one is passed.</b>
 * Through the function or the action it is the intergroup speaking, not a
 * person, so the sender name is the site's own and there is no sender
 * email to exclude from the audience. The admin compose screen passes
 * the member who wrote it, when they are one, so that it is credited to
 * them and a reply from the app can be addressed back to them — which a
 * message from the site's name cannot be. A send from a handset goes
 * through {@see \Fellowship\Rest\MessageController} instead.
 *
 * <b>Sealed here, and kept nowhere.</b> A send works out here who the message reaches,
 * asks Firebase for their devices, seals one envelope to each, and hands the envelopes
 * back, as a handset does. Firebase is told member ids, never an address. WordPress sees the text because somebody typed it here, and it isn't
 * stored. Only its subject stays, in the audit trail.
 *
 * <b>Members are named by id, as the app names them.</b> `member_ids` takes the opaque
 * ids the directory hands out, so the admin compose screen never handles an address.
 * `member_emails` is still accepted for callers that already hold them.
 *
 * <b>Everyone has to be asked for.</b> The audience is built from what was validated,
 * and is everyone only when nobody was named. Names that turn out to be nobody can't
 * become a broadcast, because an audience that reaches nobody is refused here.
 *
 * The author is a typed argument rather than an input key on purpose.
 * The input array is what other plugins hand in, and a key there would
 * let any of them put a member's name on a message that member never
 * wrote.
 */
final class MessageApi
{
    use HasLogger;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /** A sealed id can't be changed, so an audience that moves means sealing again. */
    private const SEND_ATTEMPTS = 3;

    private const STALE_AUDIENCE = 'fellowship_stale_audience';

    public function __construct(
        private readonly MessageDelivery $delivery,
        private readonly MessageSealer $sealer,
        private readonly RecipientResolver $resolver,
        private readonly AuditLogger $auditLogger,
    ) {
    }

    public function register(): void
    {
        add_action('fellowship/send_message', [$this, 'sendFromAction'], 10, 1);
    }

    /**
     * @param array<string, mixed> $input
     * @param Member|null $author The member who wrote it, or null for the
     *        intergroup. When given, the message carries their name and
     *        id, it is not delivered back to them, and the audit entry is
     *        recorded against them — what a send from the app does.
     * @return int|WP_Error The message id, or why it was refused.
     */
    public function send(array $input, ?Member $author = null): int|WP_Error
    {
        $input = $this->withNamedMembers($input);
        if ($input instanceof WP_Error) {
            return $input;
        }

        $request = MessageRequest::fromArray($input);
        if ($request instanceof WP_Error) {
            return $request;
        }

        $senderName = isset($input['sender_name']) && is_string($input['sender_name']) && trim($input['sender_name']) !== ''
            ? trim($input['sender_name'])
            : $this->siteName();
        $senderMemberId = 0;

        if ($author !== null) {
            $senderName = $author->getAnonymousName();
            $senderMemberId = $author->getId();
        }

        $audience = $this->resolver->audienceOf($request, $author?->getPersonalEmail() ?? '');
        if ($audience instanceof WP_Error) {
            return $audience;
        }

        try {
            [$id, $reached] = $this->deliver($request, $audience, $senderMemberId, $senderName);
        } catch (FirebaseUnavailable $e) {
            return $e->refusal !== ''
                ? new WP_Error($e->reason !== '' ? $e->reason : 'fellowship_refused', $e->refusal, ['status' => 400])
                : new WP_Error('fellowship_send_failed', 'Firebase could not be reached, so the message was not sent. Please try again.', ['status' => 503]);
        } catch (Throwable $e) {
            // A real fault and the caller needs to know, but it must not propagate
            // as a fatal into whatever plugin asked to send: the same reasoning as
            // the bootstrap wrapper around this method.
            self::logError('Message could not be sent', ['error' => $e->getMessage()]);

            return new WP_Error(
                'fellowship_send_failed',
                'The message could not be sent: ' . $e->getMessage(),
                ['status' => 500],
            );
        }

        // Audited because a message is addressed to named members. What is recorded
        // is who it reached, how it was addressed, and the subject, which is now the
        // only record of what a message was. See AuditDetail on why the subject earns
        // its place here. Never the body.
        //
        // Entity id 0 when there is no author: then it is the intergroup speaking, and
        // inventing a member to attribute it to would make the audit trail say
        // something untrue.
        $this->auditLogger->log(
            AuditLogger::ACTION_MESSAGE,
            AuditLogger::ENTITY_MEMBER,
            $senderMemberId,
            'message',
            AuditDetail::forSend(
                $id,
                $request->audienceType,
                $request->audienceRef,
                $request->subject,
                'Message sent from WordPress',
                $reached,
            ),
        );

        return $id;
    }

    /**
     * Ask who it reaches, seal to each device, and hand the envelopes over.
     *
     * @return array{0: int, 1: int} The message id, and how many members it reached.
     *
     * @throws FirebaseUnavailable When Firebase couldn't be asked, or refused.
     */
    private function deliver(MessageRequest $request, ResolvedAudience $reach, int $senderMemberId, string $senderName): array
    {
        $audience = [
            'senderMemberId' => $senderMemberId,
            'memberIds'      => $reach->memberIds,
            'audience'       => $reach->kind,
        ];

        for ($attempt = 1;; $attempt++) {
            $resolved = $this->delivery->resolve($audience);

            if ($resolved['devices'] === []) {
                throw new FirebaseUnavailable('Nobody to send to.', 'fellowship_no_reachable_members', 'None of those members have Link yet.');
            }

            $id = $resolved['id'];
            $envelopes = $this->sealAll($request, $id, $senderMemberId, $senderName, $resolved['devices']);

            try {
                return [$id, $this->delivery->deliver($audience, $id, $envelopes)];
            } catch (FirebaseUnavailable $e) {
                if ($e->reason !== self::STALE_AUDIENCE || $attempt >= self::SEND_ATTEMPTS) {
                    throw $e;
                }
            }
        }
    }

    /**
     * One envelope per device, in the payload a handset's send seals.
     *
     * <b>All or nothing.</b> The far side refuses a set that leaves a device out, so a
     * key that can't be used stops the send rather than quietly missing somebody.
     *
     * @param list<array{deviceId: string, publicKey: string}> $devices
     *
     * @return list<array{deviceId: string, k: string, p: string}>
     *
     * @throws FirebaseUnavailable When a device can't be sealed to.
     */
    private function sealAll(MessageRequest $request, int $id, int $senderMemberId, string $senderName, array $devices): array
    {
        $payload = [
            'id'         => $id,
            'uuid'       => wp_generate_uuid4(),
            'subject'    => $request->subject,
            'body'       => $request->body,
            'sender'     => $senderName,
            'sender_id'  => $senderMemberId,
            'created_at' => intdiv(intdiv($id, 1024), 1000),
            'reply_to'   => $request->replyToId,
        ];

        $envelopes = [];
        foreach ($devices as $device) {
            $sealed = $this->sealer->seal($payload, $device['publicKey']);
            if ($sealed === null) {
                throw new FirebaseUnavailable(
                    'A device key could not be used.',
                    'fellowship_unusable_key',
                    'One of those devices has a key that can\'t be used, so the message was not sent. Revoke that device on the Devices screen and try again.',
                );
            }

            $envelopes[] = ['deviceId' => $device['deviceId'], 'k' => $sealed['k'], 'p' => $sealed['p']];
        }

        return $envelopes;
    }

    /**
     * The action form. Returns nothing — an action cannot — so a caller
     * that needs the id or the refusal should use the function instead.
     *
     * @param array<string, mixed> $input
     */
    public function sendFromAction(array $input): void
    {
        $result = $this->send($input);

        if ($result instanceof WP_Error) {
            self::logWarning('Message refused', [
                'code'   => $result->get_error_code(),
                'reason' => $result->get_error_message(),
            ]);
        }
    }

    /**
     * Resolve `member_ids` — opaque ids from the directory — into the
     * addresses {@see MessageRequest} addresses by.
     *
     * <b>Ids that resolve to nobody are refused here, not passed on.</b>
     * A request that names nobody is a request to everyone, so dropping
     * the ids and carrying on would turn a message meant for one member
     * whose record has gone into a broadcast. Refusing before the request
     * is built is the only place that cannot happen.
     *
     * @param array<string, mixed> $input
     * @return array<string, mixed>|WP_Error
     */
    private function withNamedMembers(array $input): array|WP_Error
    {
        $ids = $input['member_ids'] ?? [];
        unset($input['member_ids']);

        if ($ids === [] || $ids === '') {
            return $input;
        }

        $named = $this->resolver->emailsForIds(is_array($ids) ? $ids : [$ids]);
        if ($named === []) {
            return new WP_Error(
                'fellowship_no_recipients',
                'That message would not reach anybody.',
                ['status' => 400],
            );
        }

        // A string is split the way MessageRequest splits one, so adding
        // the named members to it does not turn a list into one address.
        $emails = $input['member_emails'] ?? [];
        if (is_string($emails)) {
            $emails = preg_split('/[\s,;]+/', $emails) ?: [];
        }

        $input['member_emails'] = array_merge(is_array($emails) ? $emails : [], $named);

        return $input;
    }

    private function siteName(): string
    {
        $name = get_bloginfo('name');
        return is_string($name) && trim($name) !== '' ? trim($name) : 'Intergroup';
    }
}
