<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Crypto\DevicePublicKey;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\Device;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Devices\MemberGate;
use Fellowship\Logger\HasLogger;
use Scrutiny\Audit\Interfaces\AuditLogger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;
use function rest_url;

/**
 * Enrolment, and everything else a handset does about its own identity.
 *
 * <b>Two flows into one exchange.</b> Google is server-side: the handset
 * opens a browser, the browser comes back here with an authorization
 * code, this server exchanges it and hands the browser a short-lived
 * device code to carry back into the app, and the app spends that code
 * for its token. Apple is client-side: the platform sheet gives the app
 * a signed ID token directly and there is no browser leg at all. Both
 * end at {@see exchange()}, which is where the keypair is registered and
 * the token is minted — so there is one place where a device comes into
 * existence, whatever route it took to get there.
 *
 * <b>The public key is required at enrolment and is not optional
 * later.</b> A device with no key cannot be sent a sealed message, and a
 * device row that exists but cannot be messaged is exactly the silent
 * failure this plugin is arranged to avoid. It is validated before the
 * row is written, so a key that will not load fails enrolment loudly
 * rather than becoming a handset that never receives anything.
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

    /** Per-IP enrolment attempts allowed per window, and the window length. */
    private const ENROL_IP_MAX = 30;
    private const ENROL_IP_WINDOW = 900;

    /**
     * Handsets one member may have enrolled at once.
     *
     * A phone and a tablet is ordinary; five is generous. The cap exists
     * so a bug in the app's enrolment retry cannot quietly accumulate
     * hundreds of live rows, each of which is a credential and a push
     * target.
     */
    private const MAX_DEVICES_PER_MEMBER = 5;

    /** Defensive caps mirroring the column widths in WpdbDeviceRepository. */
    private const LABEL_MAX_BYTES = 200;
    private const PUSH_TOKEN_MAX_BYTES = 512;

    public function __construct(
        private readonly DeviceRepository $devices,
        private readonly DeviceTokenMinter $minter,
        private readonly DeviceCodeStore $codes,
        private readonly DeviceRedirectValidator $redirects,
        private readonly MemberGate $gate,
        private readonly CurrentDevice $currentDevice,
        private readonly ProviderRegistry $providers,
        private readonly StateStore $stateStore,
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
        register_rest_route(self::NAMESPACE, '/auth/device/start', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'start'],
            'permission_callback' => '__return_true',
            'args'                => [
                'provider' => [
                    'type'              => 'string',
                    'required'          => true,
                    'sanitize_callback' => 'sanitize_key',
                ],
                // Deliberately NOT sanitize_text_field: it strips
                // characters a URI legitimately contains. The value is
                // validated as a whole against the allow-list instead,
                // which is a stronger check than sanitising parts of it.
                'redirect_uri' => [
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
        ]);

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

        register_rest_route(self::NAMESPACE, '/auth/device/exchange', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'exchange'],
            'permission_callback' => '__return_true',
            'args'                => [
                // The Google path sends this: the one-time device code
                // the browser carried back into the app.
                'code' => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
                // The Apple path sends these instead.
                'state'    => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
                'id_token' => ['type' => 'string', 'required' => false],
                // Not sanitized as text: base64 survives it, but a future
                // key format need not, and the value is validated properly
                // by DevicePublicKey either way.
                'public_key'    => ['type' => 'string', 'required' => true],
                'label'         => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
                'platform'      => ['type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_key'],
                'push_provider' => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_key'],
                'push_token'    => ['type' => 'string', 'required' => false, 'sanitize_callback' => 'sanitize_text_field'],
            ],
        ]);

        register_rest_route(self::NAMESPACE, '/auth/device/push', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'updatePush'],
            'permission_callback' => '__return_true',
            'args'                => [
                'push_provider' => ['type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_key'],
                'push_token'    => ['type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_text_field'],
            ],
        ]);

        register_rest_route(self::NAMESPACE, '/auth/device/key', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'rotateKey'],
            'permission_callback' => '__return_true',
            'args'                => [
                'public_key' => ['type' => 'string', 'required' => true],
            ],
        ]);

        register_rest_route(self::NAMESPACE, '/auth/device/key-fault', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'reportKeyFault'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/auth/device/session', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'session'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/auth/device', [
            'methods'             => WP_REST_Server::DELETABLE,
            'callback'            => [$this, 'signOut'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * Begin a sign-in. Answers with an authorization URL for a
     * server-side provider, or a nonce for a client-side one.
     */
    public function start(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($limited = $this->rateLimited('start')) {
            return $limited;
        }

        $provider = $this->providers->get((string) $request->get_param('provider'));
        if ($provider === null) {
            return new WP_Error('fellowship_unknown_provider', 'Unknown sign-in provider.', ['status' => 400]);
        }

        if ($provider->isServerSide()) {
            $redirectUri = (string) $request->get_param('redirect_uri');
            if (!$this->redirects->isAllowed($redirectUri)) {
                return new WP_Error(
                    'fellowship_bad_redirect',
                    'That redirect target is not allowed.',
                    ['status' => 400],
                );
            }

            // A PKCE verifier only for a provider that asks for one, so
            // the transient does not carry a secret nothing will read.
            // 32 random bytes, hex-encoded to 64 characters: inside RFC
            // 7636's 43-128 range and made only of unreserved characters,
            // so it needs no escaping anywhere it travels.
            $codeVerifier = $provider->requiresPkce() ? bin2hex(random_bytes(32)) : null;

            $issued = $this->stateStore->issue($provider->name(), $redirectUri, $codeVerifier);

            return new WP_REST_Response([
                'state'             => $issued['state'],
                // The verifier is deliberately absent from this response.
                // It never leaves this server -- only its SHA-256
                // challenge goes out, on the authorization URL below --
                // and handing it to the app would undo the point of PKCE.
                'authorization_url' => $provider->getAuthorizationUrl(
                    $issued['state'],
                    $issued['nonce'],
                    $this->callbackUrl(),
                    $issued['code_verifier'],
                ),
            ], 200);
        }

        // Client-side: no browser leg, so no redirect to validate. The
        // nonce goes to the app, which puts it into the platform sign-in
        // sheet; the state comes back with the ID token so this server
        // can look the nonce up again rather than trusting the app to
        // repeat it.
        $issued = $this->stateStore->issue($provider->name(), '');

        return new WP_REST_Response([
            'state' => $issued['state'],
            'nonce' => $issued['nonce'],
        ], 200);
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
            return new WP_Error('fellowship_bad_state', 'That sign-in has expired. Please try again.', ['status' => 400]);
        }

        $redirect = $stored['device_redirect'];
        if (!$this->redirects->isAllowed($redirect)) {
            return new WP_Error('fellowship_bad_redirect', 'That redirect target is not allowed.', ['status' => 400]);
        }

        // The user declined at the provider, or the provider refused.
        $error = (string) $request->get_param('error');
        if ($error !== '') {
            return $this->redirectTo($redirect, ['error' => 'declined']);
        }

        $provider = $this->providers->get($stored['provider']);
        if ($provider === null) {
            return $this->redirectTo($redirect, ['error' => 'provider']);
        }

        $identity = $provider->handleCallback(
            (string) $request->get_param('code'),
            $stored['nonce'],
            $this->callbackUrl(),
            $stored['code_verifier'],
        );

        if ($identity === null) {
            return $this->redirectTo($redirect, ['error' => 'verification']);
        }

        // The gate is consulted here as well as at exchange, so somebody
        // whose address is not a member's is told so in the browser —
        // where they can read it — rather than by an opaque failure two
        // steps later inside the app.
        if ($this->gate->authorisedMember($identity->email) === null) {
            self::logInfo('Sign-in refused: the verified address is not a member', [
                'provider' => $identity->provider,
            ]);
            return $this->redirectTo($redirect, ['error' => 'not_a_member']);
        }

        return $this->redirectTo($redirect, ['code' => $this->codes->issue($identity)]);
    }

    /**
     * Register the keypair and mint the device token.
     *
     * The one place a device comes into existence, for both flows.
     */
    public function exchange(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        if ($limited = $this->rateLimited('exchange')) {
            return $limited;
        }

        $identity = $this->identityFor($request);
        if ($identity instanceof WP_Error) {
            return $identity;
        }

        $member = $this->gate->authorisedMember($identity->email);
        if ($member === null) {
            // Same wording whether the address is unknown or belongs to
            // somebody who may not use Link: an unauthenticated caller
            // learns nothing about who is a member.
            return new WP_Error(
                'fellowship_not_a_member',
                'That address does not match a member record. Please use the address the intergroup holds for you.',
                ['status' => 403],
            );
        }

        $platform = Device::normalisePlatform((string) $request->get_param('platform'));
        if ($platform === '') {
            return new WP_Error('fellowship_bad_platform', 'Unrecognised platform.', ['status' => 400]);
        }

        // Validated before anything is written. A key that will not load
        // must fail enrolment rather than become a device that silently
        // receives nothing.
        $publicKey = DevicePublicKey::normalise((string) $request->get_param('public_key'));
        if ($publicKey === '') {
            return new WP_Error(
                'fellowship_bad_public_key',
                'The device public key could not be read. It must be a base64 SubjectPublicKeyInfo for an RSA key of at least '
                . DevicePublicKey::MIN_BITS . ' bits.',
                ['status' => 400],
            );
        }

        $existing = $this->devices->findByMemberEmail($identity->email);
        if (count($existing) >= self::MAX_DEVICES_PER_MEMBER) {
            return new WP_Error(
                'fellowship_too_many_devices',
                'This member already has ' . self::MAX_DEVICES_PER_MEMBER . ' devices enrolled. Remove one before adding another.',
                ['status' => 409],
            );
        }

        $token = $this->minter->mint();

        try {
            $device = $this->devices->create(
                $this->minter->hash($token),
                $identity->email,
                $member->getId(),
                $this->cap((string) $request->get_param('label'), self::LABEL_MAX_BYTES),
                $platform,
                $publicKey,
                $this->pushProvider((string) $request->get_param('push_provider')),
                $this->cap((string) $request->get_param('push_token'), self::PUSH_TOKEN_MAX_BYTES),
                time(),
            );
        } catch (\RuntimeException $e) {
            self::logError('Device enrolment failed', ['error' => $e->getMessage()]);
            return new WP_Error('fellowship_enrolment_failed', $e->getMessage(), ['status' => 500]);
        }

        // Scrutiny's log takes an entity it can point at, and the entity
        // here is the member — a device is not one of its types, so it
        // goes in the detail rather than being forced into entityId.
        $this->auditLogger->log(
            AuditLogger::ACTION_CREATE,
            AuditLogger::ENTITY_MEMBER,
            $member->getId(),
            'authentication',
            'Link device enrolled via ' . $identity->provider
                . ';platform:' . $platform
                . ';device:' . $device->id,
        );

        self::logInfo('Device enrolled', ['device' => $device->id, 'platform' => $platform]);

        // The only time the raw token exists outside the handset. It is
        // not recoverable afterwards — the row holds an HMAC — so an app
        // that loses it has to enrol again. The key needs no such
        // ceremony: this server never had the private half to emit.
        return new WP_REST_Response([
            'token'  => $token,
            'device' => $this->describe($device),
            'member' => [
                'id'   => $member->getId(),
                'name' => $member->getAnonymousName(),
            ],
        ], 201);
    }

    public function updatePush(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $this->devices->updatePush(
            $device->id,
            $this->pushProvider((string) $request->get_param('push_provider')),
            $this->cap((string) $request->get_param('push_token'), self::PUSH_TOKEN_MAX_BYTES),
        );

        return new WP_REST_Response(['ok' => true], 200);
    }

    /**
     * Replace the handset's public key without re-enrolling.
     *
     * The platform invalidates a keystore entry for reasons that have
     * nothing to do with this app — the screen lock changed, a backup was
     * restored, biometrics were re-enrolled. Making that a full
     * re-enrolment would cost the member their place in the device list
     * and tell them nothing useful; letting the handset present a new key
     * keeps the row and its history.
     *
     * <b>Messages already sent stay unreadable, and here that is a fact
     * rather than a policy.</b> They were sealed to content keys wrapped
     * to the old public key, and this server never held the private half —
     * so it could not re-seal them even if it wanted to. The app clears
     * what it cannot open.
     */
    public function rotateKey(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $publicKey = DevicePublicKey::normalise((string) $request->get_param('public_key'));
        if ($publicKey === '') {
            return new WP_Error(
                'fellowship_bad_public_key',
                'The device public key could not be read.',
                ['status' => 400],
            );
        }

        if (!$this->devices->updatePublicKey($device->id, $publicKey)) {
            self::logError('A handset presented a new key and it could not be stored', [
                'device' => $device->id,
            ]);

            return new WP_Error(
                'fellowship_key_update_failed',
                'The new key could not be stored. Please try again.',
                ['status' => 500],
            );
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_UPDATE,
            AuditLogger::ENTITY_MEMBER,
            $device->memberId,
            'device_key',
            'Link device key replaced;device:' . $device->id,
        );

        return new WP_REST_Response(['ok' => true], 200);
    }

    /**
     * The handset reporting that it cannot open its messages.
     *
     * Reported rather than inferred, because this server cannot see it:
     * from here a handset with a lost private key looks perfectly healthy
     * right up until a message it cannot read.
     */
    public function reportKeyFault(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $this->devices->markKeyFault($device->id, time());

        self::logWarning('A handset reported it cannot read its messages', ['device' => $device->id]);

        return new WP_REST_Response(['ok' => true], 200);
    }

    /** Who this handset is, for an app deciding whether it is still signed in. */
    public function session(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $member = $this->currentDevice->memberFor($device);

        return new WP_REST_Response([
            'device' => $this->describe($device),
            'member' => $member === null ? null : [
                'id'   => $member->getId(),
                'name' => $member->getAnonymousName(),
            ],
        ], 200);
    }

    /**
     * Sign out: the handset revokes itself.
     *
     * Revoked rather than deleted, so the admin list can still show that
     * a device was enrolled and when it was cut off.
     */
    public function signOut(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $device = $this->authenticate($request);
        if ($device instanceof WP_Error) {
            return $device;
        }

        $this->devices->revoke($device->id, time());

        $this->auditLogger->log(
            AuditLogger::ACTION_DELETE,
            AuditLogger::ENTITY_MEMBER,
            $device->memberId,
            'authentication',
            'Link device signed out;device:' . $device->id . ';by:device',
        );

        return new WP_REST_Response(['ok' => true], 200);
    }

    /**
     * Resolve the verified identity behind an exchange, whichever flow
     * it came from.
     */
    private function identityFor(WP_REST_Request $request): VerifiedIdentity|WP_Error
    {
        $code = (string) $request->get_param('code');
        if ($code !== '') {
            $identity = $this->codes->consume($code);
            return $identity ?? new WP_Error(
                'fellowship_bad_code',
                'That sign-in code has expired or has already been used.',
                ['status' => 400],
            );
        }

        $idToken = (string) $request->get_param('id_token');
        $state   = (string) $request->get_param('state');

        if ($idToken === '' || $state === '') {
            return new WP_Error(
                'fellowship_no_credential',
                'Send either a sign-in code, or a state and an ID token.',
                ['status' => 400],
            );
        }

        $stored = $this->stateStore->consume($state);
        if ($stored === null) {
            return new WP_Error('fellowship_bad_state', 'That sign-in has expired. Please try again.', ['status' => 400]);
        }

        $provider = $this->providers->get($stored['provider']);
        if ($provider === null || $provider->isServerSide()) {
            // A server-side provider arriving here means the app sent an
            // ID token for a flow that does not produce one — a wiring
            // mistake, not a failed sign-in.
            return new WP_Error('fellowship_wrong_flow', 'That provider does not accept an ID token.', ['status' => 400]);
        }

        $identity = $provider->verifyIdToken($idToken, $stored['nonce']);

        return $identity ?? new WP_Error(
            'fellowship_bad_id_token',
            'That sign-in could not be verified.',
            ['status' => 401],
        );
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

    /** @param array<string, string> $params */
    private function redirectTo(string $uri, array $params): WP_REST_Response
    {
        $response = new WP_REST_Response(null, 302);
        $response->header('Location', $this->redirects->withParams($uri, $params));
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

    /**
     * Only transports we actually implement. An unrecognised value
     * becomes "pull only" rather than a bad request: a handset that
     * cannot register for push should still enrol and collect its
     * messages by polling.
     */
    private function pushProvider(string $claimed): string
    {
        return strtolower(trim($claimed)) === Device::PUSH_FCM ? Device::PUSH_FCM : Device::PUSH_NONE;
    }

    private function cap(string $value, int $maxBytes): string
    {
        $value = trim($value);
        return strlen($value) <= $maxBytes ? $value : substr($value, 0, $maxBytes);
    }

    /**
     * What the app is told about its own row. Never the token hash, and
     * never another device's anything.
     *
     * @return array<string, mixed>
     */
    private function describe(Device $device): array
    {
        return [
            'id'         => $device->id,
            'label'      => $device->label,
            'platform'   => $device->platform,
            'push'       => $device->wantsPush(),
            'created_at' => $device->createdAt,
        ];
    }
}
