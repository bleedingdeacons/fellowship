<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\AudienceProviders;
use Fellowship\Auth\AudienceRegistry;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordResetResult;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\MemberGate;
use Fellowship\Logger\HasLogger;
use Guardian\ProviderRegistry;
use Scrutiny\Audit\Interfaces\AuditLogger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;
use function rest_url;

/**
 * The browser sign-in's callback, and setting a Link password.
 *
 * <b>The callback serves other plugins' audiences.</b> Freedom starts a
 * browser sign-in through the {@see \Fellowship\Auth\IdentityBroker}, the provider
 * sends the browser back here, and the audience that started it decides
 * where its one-time code may go and who may have one. Link no longer signs
 * in this way: it uses Firebase, and its old device routes are gone.
 *
 * <b>The password routes are Link's.</b> A member asks for a code by email
 * and sets a password with it, which Link then signs in with through
 * {@see FirebaseIdentityController}.
 */
final class DeviceAuthController
{
    use HasLogger;
    use RequiresSecureTransport;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public const NAMESPACE = 'fellowship/v1';

    /** Per-IP attempts allowed per window, and the window length. */
    private const ENROL_IP_MAX = 30;
    private const ENROL_IP_WINDOW = 900;

    /** The provider for an audience's callback, which may be its own client. See BringsOwnClient. */
    private readonly AudienceProviders $clients;

    public function __construct(
        ProviderRegistry $providers,
        private readonly StateStore $stateStore,
        private readonly DeviceCodeStore $codes,
        private readonly MemberGate $gate,
        private readonly RateLimiter $rateLimiter,
        private readonly AuditLogger $auditLogger,
        private readonly PasswordAuthenticator $passwords,
        private readonly AudienceRegistry $audiences,
        ?AudienceProviders $clients = null,
    ) {
        // Defaulted, so a caller that brings no client gets Fellowship's
        // providers only.
        $this->clients = $clients ?? AudienceProviders::withoutOverrides($providers);
    }

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        // Only what is still called. Link signs in through Firebase now, so the
        // old device routes (start, exchange, password, push, key, key-fault,
        // session, sign-out) are not registered: each was a way in that nothing
        // uses. The callback stays for other audiences' browser sign-ins, such
        // as Freedom's, and the password routes for setting a Link password.
        register_rest_route(self::NAMESPACE, '/auth/callback', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'callback'],
            'permission_callback' => '__return_true',
            'args'                => [
                'code'  => ['type' => 'string', 'required' => false],
                'state' => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
                'error' => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
            ],
        ]);

        // Ask for a set-or-reset link. Always answers the same thing.
        register_rest_route(self::NAMESPACE, '/auth/password/request', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'requestPassword'],
            'permission_callback' => '__return_true',
            'args'                => [
                'email' => ['type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_email'],
            ],
        ]);

        // Complete one, with the token from the emailed link.
        register_rest_route(self::NAMESPACE, '/auth/password/complete', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'completePassword'],
            'permission_callback' => '__return_true',
            'args'                => [
                'token'    => ['type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_text_field'],
                'password' => ['type' => 'string', 'required' => true],
            ],
        ]);
    }

    /**
     * The browser leg's landing point, for server-side providers.
     *
     * Ends in a redirect back into the app carrying a one-time device
     * code — never a token. See {@see DeviceCodeStore} for why the
     * browser is not trusted with the credential itself.
     */
    public function callback(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        $state = (string) $request->get_param('state');
        $stored = $this->stateStore->consume($state);
        if ($stored === null) {
            // Includes a replayed callback, since consume() is one-shot.
            return $this->refused(
                new WP_Error('fellowship_bad_state', 'That sign-in has expired. Please try again.', ['status' => 400]),
                'callback',
                '',
                $request,
            );
        }

        // Whoever started this sign-in decides where its code may go and who
        // may have one: another plugin that registered an audience with the
        // IdentityBroker. See SignInAudience. Never Link: it signs in through
        // Firebase, its name is reserved, and a state stored for it finds no
        // audience here.
        $audience = $this->audiences->get($stored['audience']);
        if ($audience === null) {
            return $this->refused(
                new WP_Error('fellowship_bad_state', 'That sign-in has expired. Please try again.', ['status' => 400]),
                'callback',
                $stored['provider'],
                $request,
            );
        }

        $redirect = $stored['device_redirect'];
        if (!$audience->allowsRedirect($redirect, $stored['context'])) {
            return $this->refused(
                new WP_Error('fellowship_bad_redirect', 'That redirect target is not allowed.', ['status' => 400]),
                'callback',
                $stored['provider'],
                $request,
            );
        }

        // The user declined at the provider, or the provider refused.
        $error = (string) $request->get_param('error');
        if ($error !== '') {
            return $this->refusedInBrowser($redirect, 'declined', $stored['provider'], ['provider_error' => $error]);
        }

        // The same client the sign-in started with: the audience is asked
        // again, with the context it was asked with then.
        $provider = $this->clients->for($stored['provider'], $audience, $stored['context']);
        if ($provider === null) {
            return $this->refusedInBrowser($redirect, 'provider', $stored['provider']);
        }

        $proven = $provider->handleCallback(
            (string) $request->get_param('code'),
            $stored['nonce'],
            $this->callbackUrl(),
            $stored['code_verifier'],
        );

        if ($proven === null) {
            return $this->refusedInBrowser($redirect, 'verification', $stored['provider']);
        }

        // Into Fellowship's own type, which the audience contract carries.
        $identity = VerifiedIdentity::fromProvider($proven);

        // The audience is consulted here as well as at its exchange, so
        // somebody it will not admit is told so in the browser -- where
        // they can read it -- rather than by an opaque failure two steps
        // later inside the app.
        $refusal = $audience->refusalFor($identity, $stored['context']);
        if ($refusal !== null) {
            return $this->refusedInBrowser($redirect, $refusal, $stored['provider'], ['address' => $identity->email]);
        }

        return $this->redirectTo($redirect, [
            'code' => $this->codes->issue($identity, $audience->name(), $stored['context']),
        ]);
    }

    /**
     * Ask for a set-or-reset link.
     *
     * <b>The answer never varies.</b> Same body, same status, whether the
     * address belongs to a member, to somebody who may not use Link, or
     * to nobody at all. The send is queued past the response as well, so
     * the two branches cost the same time as well as saying the same
     * thing — a synchronous SMTP round trip on one branch and a return on
     * the other is a difference an attacker can measure.
     */
    public function requestPassword(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($limited = $this->rateLimited('start')) {
            return $limited;
        }

        $this->passwords->beginReset((string) $request->get_param('email'), time());

        return new WP_REST_Response([
            'sent'    => true,
            'message' => 'If that address belongs to a member, a link is on its way. It expires in an hour.',
        ], 200);
    }

    /**
     * Set the password, using the token from the emailed link.
     *
     * Answers no session: setting a password is not signing in, and the
     * app returns to the sign-in screen to use it. That keeps this
     * endpoint free of the device-enrolment arguments it would otherwise
     * need, and means a link opened on the wrong handset cannot enrol it.
     */
    public function completePassword(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($limited = $this->rateLimited('exchange')) {
            return $limited;
        }

        $result = $this->passwords->completeReset(
            (string) $request->get_param('token'),
            (string) $request->get_param('password'),
            time(),
        );

        if ($result->status === PasswordResetResult::INVALID_TOKEN) {
            return new WP_Error(
                'fellowship_bad_reset_token',
                'That link has expired or has already been used. Please ask for a new one.',
                ['status' => 400],
            );
        }

        if ($result->status === PasswordResetResult::WEAK_PASSWORD) {
            // 422 rather than 400: the request was well formed and the
            // token was good. The link stays usable, so the member can
            // try a different password without asking for another email.
            return new WP_Error('fellowship_weak_password', $result->message, ['status' => 422]);
        }

        $member = $this->gate->authorisedMember($result->email);
        if ($member !== null) {
            $this->auditLogger->log(
                AuditLogger::ACTION_UPDATE,
                AuditLogger::ENTITY_MEMBER,
                $member->getId(),
                'authentication',
                'Link password set via emailed link',
            );
        }

        return new WP_REST_Response(['ok' => true], 200);
    }

    private function rateLimited(string $bucket): ?WP_Error
    {
        $key = 'enrol_' . $bucket . '_' . $this->rateLimiter->clientIp();

        if (!$this->rateLimiter->overLimit($key, self::ENROL_IP_MAX, self::ENROL_IP_WINDOW)) {
            return null;
        }

        return new WP_Error(
            'fellowship_rate_limited',
            'Too many sign-in attempts. Please wait a few minutes and try again.',
            ['status' => 429],
        );
    }

    /**
     * Log a refused sign-in, and answer the refusal unchanged.
     *
     * <b>Why a refusal is logged at all.</b> The audit log records a
     * handset once it is enrolled, so one that is never let in leaves
     * nothing behind. Nor can it say for itself: Link is only told where
     * to ship its logs once it has signed in. This line is the one record
     * of why a handset was turned away.
     *
     * Rate-limited requests are the exception, and pass by without
     * coming through here: they are the flood, and a line each would
     * let a flood fill the log as well.
     */
    private function refused(
        WP_Error $refusal,
        string $step,
        string $flow,
        WP_REST_Request $request,
        string $address = '',
    ): WP_Error {
        $data = $refusal->get_error_data();

        self::logRefusal([
            'step'     => $step,
            'flow'     => $flow,
            'refusal'  => $refusal->get_error_code(),
            'status'   => is_array($data) ? (int) ($data['status'] ?? 0) : 0,
            'platform' => (string) $request->get_param('platform'),
            'address'  => $address,
        ]);

        return $refusal;
    }

    /**
     * The callback's own refusals, which go back to the app as an error
     * on its redirect rather than as a REST error.
     *
     * @param array<string, string> $context
     */
    private function refusedInBrowser(string $redirect, string $refusal, string $flow, array $context = []): WP_REST_Response
    {
        self::logRefusal(['step' => 'callback', 'flow' => $flow, 'refusal' => $refusal] + $context);

        return $this->redirectTo($redirect, ['error' => $refusal]);
    }

    /**
     * The address goes in masked: enough for an administrator to see
     * which account was offered — most often a Google address other than
     * the one the intergroup holds — without the log becoming a list of
     * who tried.
     *
     * @param array<string, string|int> $context
     */
    private static function logRefusal(array $context): void
    {
        if (isset($context['address'])) {
            $context['address'] = self::maskAddress((string) $context['address']);
        }

        self::logWarning('A sign-in was refused', array_filter($context, static fn($value): bool => $value !== ''));
    }

    /** `member@example.org` becomes `m***@example.org`. */
    private static function maskAddress(string $address): string
    {
        $address = trim($address);
        $at      = strrpos($address, '@');

        if ($address === '' || $at === false || $at === 0) {
            return $address === '' ? '' : '***';
        }

        return mb_substr($address, 0, 1) . '***' . substr($address, $at);
    }

    /** @param array<string, string> $params */
    private function redirectTo(string $uri, array $params): WP_REST_Response
    {
        $response = new WP_REST_Response(null, 302);
        $response->header('Location', rtrim($uri, '?&') . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        // Belt and braces alongside the namespace-wide no-store filter in
        // Plugin::init(): this particular response carries a credential
        // in its Location header.
        $response->header('Cache-Control', 'no-store');

        return $response;
    }

    private function callbackUrl(): string
    {
        return rest_url(self::NAMESPACE . '/auth/callback');
    }
}
