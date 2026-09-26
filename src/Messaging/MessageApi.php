<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

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

    public function __construct(
        private readonly MessageDispatcher $dispatcher,
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
     * @return int|WP_Error The stored message id, or why it was refused.
     */
    public function send(array $input, ?Member $author = null): int|WP_Error
    {
        $request = MessageRequest::fromArray($input);
        if ($request instanceof WP_Error) {
            return $request;
        }

        $senderName = isset($input['sender_name']) && is_string($input['sender_name']) && trim($input['sender_name']) !== ''
            ? trim($input['sender_name'])
            : $this->siteName();
        $senderEmail = '';
        $senderMemberId = 0;

        if ($author !== null) {
            $senderName = $author->getAnonymousName();
            $senderEmail = strtolower(trim($author->getPersonalEmail()));
            $senderMemberId = $author->getId();
        }

        try {
            $members = $this->resolver->resolve($request, $senderEmail);
            $message = $this->dispatcher->dispatch($request, $members, $senderEmail, $senderMemberId, $senderName);
        } catch (Throwable $e) {
            // A storage failure here is a real fault and the caller needs
            // to know, but it must not propagate as a fatal into whatever
            // plugin asked to send — the same reasoning as the bootstrap
            // wrapper around this method.
            self::logError('Message could not be sent', ['error' => $e->getMessage()]);

            return new WP_Error(
                'fellowship_send_failed',
                'The message could not be sent: ' . $e->getMessage(),
                ['status' => 500],
            );
        }

        // Audited because a message is personal data addressed to named
        // members. What is recorded is who it reached, how it was
        // addressed, and the subject — not the body, which is already in
        // a table Scrutiny does not need a second copy of. See
        // AuditDetail on why the subject is the one piece of the message
        // text that earns its place here.
        //
        // Entity id 0 when there is no author: then it is the intergroup
        // speaking, and inventing a member to attribute it to would make
        // the audit trail say something untrue.
        $this->auditLogger->log(
            AuditLogger::ACTION_MESSAGE,
            AuditLogger::ENTITY_MEMBER,
            $senderMemberId,
            'message',
            AuditDetail::forMessage($message, 'Message sent from WordPress', count($members)),
        );

        return $message->id;
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

    private function siteName(): string
    {
        $name = get_bloginfo('name');
        return is_string($name) && trim($name) !== '' ? trim($name) : 'Intergroup';
    }
}
