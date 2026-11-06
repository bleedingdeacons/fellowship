<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\ServiceCaller;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRequest;
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
 * What Link's Cloud Functions ask about members.
 *
 * <b>The member list stays in WordPress.</b> Nothing about a member is copied
 * to Firebase, so when a Function needs to know whether somebody may enrol, or
 * who a message reaches, it asks here. Member data leaves this server only as
 * the answer to these two routes, and those answers are opaque ids: an address
 * goes in, but none comes back out.
 *
 * Only {@see ServiceCaller} gets an answer, whatever the route table says. As
 * with every route here the credential is checked inside the handler, because
 * a WordPress permission callback has no way to read a bearer token.
 *
 * Nothing calls these yet. They arrive ahead of the Functions that will.
 */
final class ServiceController
{
    use RequiresSecureTransport;

    public const NAMESPACE = 'fellowship/v1';

    /** The prefix of these routes, and the audience of a caller's token. */
    public const SERVICE_PATH = self::NAMESPACE . '/service';

    private const ORIGIN_MEMBER = 'member';
    private const ORIGIN_ADMIN = 'admin';

    public function __construct(
        private readonly ServiceCaller $caller,
        private readonly MemberRepository $members,
        private readonly MemberGate $gate,
        private readonly RecipientResolver $resolver,
        private readonly Settings $settings,
        private readonly AuditLogger $auditLogger,
    ) {
    }

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/service/member', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'member'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/service/audience', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'audience'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * May this person use Link?
     *
     * Takes an email, from a verified sign-in, or a member id, from a claim
     * Fellowship minted itself. Somebody unknown is an ordinary answer rather
     * than an error, because "no" is what the caller came to find out.
     */
    public function member(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($refused = $this->refusal($request)) {
            return $refused;
        }

        $email = strtolower(trim((string) $request->get_param('email')));
        $id = (int) $request->get_param('member_id');

        if (($email === '') === ($id <= 0)) {
            return new WP_Error(
                'fellowship_bad_request',
                'Name one member, by email or by id.',
                ['status' => 400],
            );
        }

        $member = $email !== '' ? $this->members->findByEmail($email) : $this->members->findById($id);
        $admitted = $this->gate->isAuthorised($member);

        if ($member !== null) {
            $this->auditLogger->log(
                AuditLogger::ACTION_VIEW,
                AuditLogger::ENTITY_MEMBER,
                $member->getId(),
                'service-member',
                'Link Functions member check;admitted:' . ($admitted ? '1' : '0'),
            );
        }

        return new WP_REST_Response([
            'member_id' => $member?->getId() ?? 0,
            'admitted'  => $admitted,
        ], 200);
    }

    /**
     * Who does a message reach?
     *
     * Answers member ids, with the sender left out. The same rules as a send
     * from a handset: only members may send, the whole fellowship is not a
     * handset's to address, and committees and all GSRs need the site's
     * permission. An `admin` origin is the Compose screen, which holds the
     * capability those rules exist to protect.
     *
     * <b>Naming nobody is refused, never read as everyone.</b> In
     * {@see MessageRequest} an empty audience means everyone, so names that all
     * turn out stale must not fall through to it. Everyone has to be asked for.
     */
    public function audience(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($refused = $this->refusal($request)) {
            return $refused;
        }

        $origin = (string) $request->get_param('origin');
        $origin = $origin === '' ? self::ORIGIN_MEMBER : $origin;
        if ($origin !== self::ORIGIN_MEMBER && $origin !== self::ORIGIN_ADMIN) {
            return new WP_Error('fellowship_bad_request', 'Unknown origin.', ['status' => 400]);
        }
        $isAdmin = $origin === self::ORIGIN_ADMIN;

        $senderId = max(0, (int) $request->get_param('sender_member_id'));
        $sender = $senderId > 0 ? $this->members->findById($senderId) : null;

        if (!$isAdmin && !$this->gate->isAuthorised($sender)) {
            return new WP_Error(
                'fellowship_not_a_member',
                'That address no longer matches a member record.',
                ['status' => 403],
            );
        }

        $committees = $request->get_param('committees');
        $committees = is_array($committees) ? $committees : [];
        $gsrs = $request->get_param('gsrs');
        $wantsGsrs = $gsrs !== null && $gsrs !== false && $gsrs !== '';
        $wantsPart = $committees !== [] || $wantsGsrs;

        if (!$isAdmin && $wantsPart && !$this->settings->allowsCommitteeSendFromApp()) {
            return new WP_Error(
                'fellowship_committee_send_disabled',
                'Sending to a committee or to all GSRs from the app is not enabled on this site.',
                ['status' => 403],
            );
        }

        $ids = $request->get_param('member_ids');
        $named = is_array($ids) && $ids !== [];
        $everyone = filter_var($request->get_param('everyone'), FILTER_VALIDATE_BOOLEAN);

        // A handset may not address the whole fellowship, and a request that
        // asks for everyone and somebody in particular has not said which.
        if ($everyone && (!$isAdmin || $named || $wantsPart)) {
            return self::noAudience();
        }

        $emails = $this->resolver->emailsForIds($ids);

        if ($named && $emails === [] && !$wantsPart) {
            return self::noRecipients();
        }

        $built = MessageRequest::forAudience([
            'committees'    => $committees,
            'gsrs'          => $wantsGsrs,
            'member_emails' => $emails,
        ]);
        if ($built instanceof WP_Error) {
            return $built;
        }

        // Also catches a committee list that normalised away to nothing.
        if (!$everyone && $built->audienceType === Message::AUDIENCE_ALL) {
            return self::noAudience();
        }

        $senderEmail = $sender !== null ? strtolower(trim($sender->getPersonalEmail())) : '';
        $memberIds = array_map(
            static fn(array $recipient): int => $recipient['member_id'],
            $this->resolver->resolve($built, $senderEmail),
        );

        if ($memberIds === []) {
            return self::noRecipients();
        }

        sort($memberIds);

        $this->auditLogger->log(
            AuditLogger::ACTION_VIEW,
            AuditLogger::ENTITY_MEMBER,
            $senderId,
            'service-audience',
            'Link Functions audience;origin:' . $origin . ';members:' . count($memberIds),
        );

        return new WP_REST_Response(['member_ids' => $memberIds], 200);
    }

    private function refusal(WP_REST_Request $request): ?WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if (!$this->caller->isConfigured()) {
            return new WP_Error(
                'fellowship_firebase_not_configured',
                'Firebase is not configured on this site.',
                ['status' => 503],
            );
        }

        if (!$this->caller->accepts((string) $request->get_header('authorization'))) {
            return new WP_Error('fellowship_unauthenticated', 'This caller is not recognised.', ['status' => 401]);
        }

        return null;
    }

    private static function noAudience(): WP_Error
    {
        return new WP_Error('fellowship_no_audience', 'Choose who this message is for.', ['status' => 400]);
    }

    private static function noRecipients(): WP_Error
    {
        return new WP_Error('fellowship_no_recipients', 'That message would not reach anybody.', ['status' => 400]);
    }
}
