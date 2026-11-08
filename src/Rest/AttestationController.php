<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\SignInTokens;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\DeviceResolution;
use Fellowship\Devices\FirebaseDeviceResolution;
use Fellowship\Devices\FirebaseDevices;
use Fellowship\Devices\MemberGate;
use Fellowship\Firebase\AttestationSigner;
use Fellowship\Messaging\AudienceResolver;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Unity\Members\Interfaces\MemberRepository;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;

/**
 * What a phone fetches here and hands to the Functions.
 *
 * <b>The member list stays in WordPress.</b> The Functions need to know whether a
 * sign-in is a member, and who a message reaches, and only this site can say. They
 * used to ask it themselves, but SiteGround challenges Google Cloud's shared
 * addresses. So the phone asks instead, and carries the signed answer. See
 * {@see AttestationSigner}.
 *
 * - `POST /attest/member`, with a fresh Firebase sign-in as the bearer token. For
 *   enrolling, replacing a key and taking over a device.
 * - `POST /attest/audience`, with a live device's token. `memberIds`, `committees`
 *   and `gsrs` in the body, as a send names them.
 *
 * Member data leaves only as opaque ids, signed for the Functions. An address goes
 * in, inside a sign-in, but none comes back out.
 *
 * As with every route here the credential is checked inside the handler, because a
 * WordPress permission callback has no way to read a bearer token.
 */
final class AttestationController
{
    use RequiresSecureTransport;

    public const NAMESPACE = 'fellowship/v1';

    /** Generous for people signing in; a script trying sign-ins hits it. */
    private const MEMBER_IP_MAX = 30;

    /** Each send asks once, and a phone may send 20 in the window. Some share an address. */
    private const AUDIENCE_IP_MAX = 120;

    private const IP_WINDOW = 900;

    public function __construct(
        private readonly AttestationSigner $signer,
        private readonly SignInTokens $signIns,
        private readonly FirebaseDevices $devices,
        private readonly MemberRepository $members,
        private readonly MemberGate $gate,
        private readonly AudienceResolver $audiences,
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
        register_rest_route(self::NAMESPACE, '/attest/member', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'member'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/attest/audience', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'audience'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * This sign-in is this member, for the Functions to enrol.
     *
     * Refused in the words the Functions used, so a phone shows the same thing.
     */
    public function member(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($refused = $this->refusal('attest_member_', self::MEMBER_IP_MAX)) {
            return $refused;
        }

        $signIn = $this->signIns->verify(self::bearer($request));
        if ($signIn === null) {
            return new WP_Error(
                'fellowship_bad_id_token',
                'That sign-in could not be verified.',
                ['status' => 401],
            );
        }

        $member = $signIn->email !== ''
            ? $this->members->findByEmail($signIn->email)
            : $this->members->findById($signIn->memberId);

        if ($member === null || !$this->gate->isAuthorised($member)) {
            return new WP_Error(
                'fellowship_not_a_member',
                'That address does not match a member record.',
                ['status' => 403],
            );
        }

        $attestation = $this->signer->sign(AttestationSigner::KIND_MEMBER, $signIn->uid, [
            'memberId' => $member->getId(),
        ]);
        if ($attestation === null) {
            return self::notConfigured();
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_VIEW,
            AuditLogger::ENTITY_MEMBER,
            $member->getId(),
            'attest-member',
            'Link sign-in attested;by:' . ($signIn->email !== '' ? 'address' : 'password'),
        );

        return new WP_REST_Response(['attestation' => $attestation], 200);
    }

    /**
     * Who this device's message reaches, for the Functions to seal and deliver to.
     *
     * The sender is the device's member, never anybody the body names.
     */
    public function audience(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($refused = $this->refusal('attest_audience_', self::AUDIENCE_IP_MAX)) {
            return $refused;
        }

        $resolved = $this->devices->resolve(self::bearer($request));
        $device = $resolved->device;
        if ($device === null) {
            return match ($resolved->refusal) {
                FirebaseDeviceResolution::UNAVAILABLE => new WP_Error(
                    'fellowship_unavailable',
                    'This device could not be checked just now. Please try again.',
                    ['status' => 503],
                ),
                DeviceResolution::NOT_A_MEMBER => new WP_Error(
                    'fellowship_not_a_member',
                    'That address no longer matches a member record.',
                    ['status' => 403],
                ),
                default => new WP_Error('fellowship_unauthenticated', 'This device is not signed in.', ['status' => 401]),
            };
        }

        $audience = $this->audiences->fromHandset(
            $device->email,
            $request->get_param('memberIds'),
            $request->get_param('committees'),
            $request->get_param('gsrs'),
            $request->get_param('everyone'),
        );
        if ($audience instanceof WP_Error) {
            return $audience;
        }

        $attestation = $this->signer->sign(AttestationSigner::KIND_AUDIENCE, $device->id, [
            'senderMemberId' => $device->memberId,
            'memberIds'      => $audience->memberIds,
            'audience'       => $audience->kind,
        ]);
        if ($attestation === null) {
            return self::notConfigured();
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_VIEW,
            AuditLogger::ENTITY_MEMBER,
            $device->memberId,
            'attest-audience',
            'Link audience attested;audience:' . $audience->kind
                . ';members:' . count($audience->memberIds)
                . ';device:' . $device->id,
        );

        return new WP_REST_Response(['attestation' => $attestation], 200);
    }

    private function refusal(string $limitKey, int $max): ?WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($this->rateLimiter->overLimit($limitKey . $this->rateLimiter->clientIp(), $max, self::IP_WINDOW)) {
            return new WP_Error(
                'fellowship_rate_limited',
                'Too many attempts. Please wait a few minutes and try again.',
                ['status' => 429],
            );
        }

        if (!$this->signer->isConfigured()) {
            return self::notConfigured();
        }

        return null;
    }

    private static function bearer(WP_REST_Request $request): string
    {
        return preg_match('/^\s*Bearer\s+(\S+)\s*$/i', (string) $request->get_header('authorization'), $matches)
            ? $matches[1]
            : '';
    }

    private static function notConfigured(): WP_Error
    {
        return new WP_Error(
            'fellowship_firebase_not_configured',
            'Firebase is not configured on this site.',
            ['status' => 503],
        );
    }
}
