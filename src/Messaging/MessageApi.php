<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Logger\HasLogger;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Throwable;
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
 * <b>A send from here has no member behind it.</b> It is the intergroup
 * speaking, not a person, so the sender name is the site's own and there
 * is no sender email to exclude from the audience. A send from a handset
 * goes through {@see \Fellowship\Rest\MessageController} instead, which
 * has a member and passes one.
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
     * @return int|WP_Error The stored message id, or why it was refused.
     */
    public function send(array $input): int|WP_Error
    {
        $request = MessageRequest::fromArray($input);
        if ($request instanceof WP_Error) {
            return $request;
        }

        $senderName = isset($input['sender_name']) && is_string($input['sender_name']) && trim($input['sender_name']) !== ''
            ? trim($input['sender_name'])
            : $this->siteName();

        try {
            $members = $this->resolver->resolve($request);
            $message = $this->dispatcher->dispatch($request, $members, '', 0, $senderName);
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
        // members. What is recorded is who it reached and how it was
        // addressed — not the body, which is already in a table Scrutiny
        // does not need a second copy of.
        //
        // Entity id 0: this send has no member behind it. It is the
        // intergroup speaking, and inventing a member to attribute it to
        // would make the audit trail say something untrue.
        $this->auditLogger->log(
            AuditLogger::ACTION_MESSAGE,
            AuditLogger::ENTITY_MEMBER,
            0,
            'message',
            'Message sent from WordPress;message:' . $message->id
                . ';audience:' . $message->audienceType
                . ($message->audienceRef !== '' ? ';ref:' . $message->audienceRef : '')
                . ';recipients:' . count($members),
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
