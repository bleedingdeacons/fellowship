<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\FirebaseCustomTokenMinter;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Logger\HasLogger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;

/**
 * Turns a member's Unity password into a Firebase sign-in.
 *
 * The password stays with Unity, shared with Reach, Sentinel and Amber, and
 * Firebase never sees it or the member's address. This checks it and answers
 * with a short-lived custom token whose uid is `pw_<member id>`. The handset
 * uses that only to prove who it is when it enrols.
 *
 * It enrols nothing and creates no device. Setting and resetting a password
 * stay at `/auth/password/request` and `/auth/password/complete`.
 *
 * Nothing calls this yet. It arrives ahead of the Link build that will.
 */
final class FirebaseIdentityController
{
    use HasLogger;
    use RequiresSecureTransport;

    public const NAMESPACE = 'fellowship/v1';

    /** The same allowance as enrolling with a password, per address. */
    private const IP_MAX = 30;
    private const IP_WINDOW = 900;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly PasswordAuthenticator $passwords,
        private readonly MemberGate $gate,
        private readonly FirebaseCustomTokenMinter $minter,
        private readonly RateLimiter $rateLimiter,
        private readonly Settings $settings,
    ) {
    }

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/auth/identity/password', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'password'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/backend', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'backend'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * Which back end Link should use, asked before anybody has signed in.
     *
     * Open on purpose: a phone needs the answer to know how to sign in, and
     * which of two back ends a site uses tells nobody anything about a member.
     */
    public function backend(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        return new WP_REST_Response(['backend' => $this->settings->getLinkBackend()], 200);
    }

    public function password(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($this->rateLimiter->overLimit('identity_' . $this->rateLimiter->clientIp(), self::IP_MAX, self::IP_WINDOW)) {
            return new WP_Error(
                'fellowship_rate_limited',
                'Too many sign-in attempts. Please wait a few minutes and try again.',
                ['status' => 429],
            );
        }

        // Before the password, so a site with no Firebase does not spend a
        // member's attempts on a sign-in that could never finish.
        if (!$this->minter->isConfigured()) {
            return self::notConfigured();
        }

        $identity = $this->passwords->attemptLogin(
            (string) $request->get_param('email'),
            (string) $request->get_param('password'),
            time(),
        );

        $member = $identity !== null ? $this->gate->authorisedMember($identity->email) : null;

        if ($member === null) {
            // One answer for an unknown address, an address with no password,
            // a wrong password, a locked account and somebody who is no longer
            // a member. Telling them apart would say who belongs to the
            // fellowship, which is the thing this flow is careful about.
            self::logNotice('Password sign-in for Firebase refused');

            return new WP_Error('fellowship_bad_credentials', 'Email or password is incorrect.', ['status' => 401]);
        }

        $token = $this->minter->mint('pw_' . $member->getId(), [
            'memberId' => $member->getId(),
            'identity' => 'password',
        ]);

        return $token !== null
            ? new WP_REST_Response(['token' => $token], 200)
            : self::notConfigured();
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
