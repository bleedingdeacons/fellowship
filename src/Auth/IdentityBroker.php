<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Guardian\ProviderRegistry;
use WP_Error;

use function rest_url;

/**
 * What another plugin may ask of Fellowship's sign-in: a Google-verified
 * address, or a live Link enrolment.
 *
 * <b>Why a broker rather than a second copy.</b> Reach and Fellowship
 * each carry their own OAuth classes, line for line, because neither
 * could use the other's. A third copy for Freedom would be a third place
 * for a JWT check to drift. So the browser leg stays here, with the one
 * registered redirect URI it already has, and another plugin reaches it
 * through this — registering a {@see SignInAudience} that owns the two
 * rules Link's flow used to hard-code: where a code may be sent, and to
 * whom. An audience may also bring its own OAuth client, so its people see
 * its own consent screen rather than Link's: see {@see BringsOwnClient}.
 *
 * <b>Two ways in.</b>
 *
 * - {@see begin()} and {@see redeem()}: the browser leg on another
 *   plugin's behalf. The plugin's own route starts it and its own route
 *   spends the code; this only guarantees the code it gets back was
 *   issued for it.
 * - {@see sessionFor()}: a handset already signed in to Link presents its
 *   Link device token instead of signing in again. That token was minted
 *   after a Google sign-in and the member gate is re-run on it here, so
 *   it proves exactly what a second trip through the browser would have,
 *   without putting the member through one.
 *
 * Every class this names is on the must-agree list in the README: a
 * second plugin now depends on them.
 */
final class IdentityBroker
{
    /** Enough for an application slug and a PKCE challenge, with room to spare. */
    public const MAX_CONTEXT_BYTES = 512;

    /** Fellowship's provider, or the audience's own client. See BringsOwnClient. */
    private readonly AudienceProviders $clients;

    public function __construct(
        private readonly AudienceRegistry $audiences,
        ProviderRegistry $providers,
        private readonly StateStore $stateStore,
        private readonly DeviceCodeStore $codes,
        private readonly CurrentDevice $currentDevice,
        private readonly DeviceRepository $devices,
        private readonly MemberGate $gate,
        ?AudienceProviders $clients = null,
    ) {
        // Defaulted, and last, so a caller written before audiences could
        // bring a client -- Freedom's test harness builds this -- still
        // compiles, and gets Fellowship's providers only.
        $this->clients = $clients ?? AudienceProviders::withoutOverrides($providers);
    }

    public function registerAudience(SignInAudience $audience): void
    {
        $this->audiences->register($audience);
    }

    /**
     * Start a browser sign-in for $audience.
     *
     * The authorization URL returns to Fellowship's own callback, so the
     * provider's console needs nothing new; the callback then asks the
     * audience where the code may go and whether this person may have one.
     *
     * @return array{state: string, authorization_url: string}|WP_Error
     */
    public function begin(string $provider, string $audience, string $context, string $redirectUri): array|WP_Error
    {
        if ($audience === LinkAudience::NAME) {
            // Link starts at /auth/device/start. Starting it here would
            // skip nothing, but it would be a second way in to keep in
            // step with the first.
            return new WP_Error('fellowship_wrong_audience', 'Link signs in through its own route.', ['status' => 400]);
        }

        $target = $this->audiences->get($audience);
        if ($target === null) {
            return new WP_Error('fellowship_unknown_audience', 'Unknown sign-in audience.', ['status' => 400]);
        }

        if (strlen($context) > self::MAX_CONTEXT_BYTES) {
            return new WP_Error('fellowship_bad_context', 'The sign-in context is too long.', ['status' => 400]);
        }

        $oauth = $this->clients->for($provider, $target, $context);
        if ($oauth === null) {
            return new WP_Error('fellowship_unknown_provider', 'Unknown sign-in provider.', ['status' => 400]);
        }

        if (!$oauth->isServerSide()) {
            // A client-side provider has no browser leg, so there is no
            // callback for the audience's rules to be applied in.
            return new WP_Error('fellowship_wrong_flow', 'That provider has no browser sign-in.', ['status' => 400]);
        }

        if (!$target->allowsRedirect($redirectUri, $context)) {
            return new WP_Error('fellowship_bad_redirect', 'That redirect target is not allowed.', ['status' => 400]);
        }

        // As in DeviceAuthController::start(): a verifier only for a
        // provider that wants one, and it never leaves this server.
        $codeVerifier = $oauth->requiresPkce() ? bin2hex(random_bytes(32)) : null;

        $issued = $this->stateStore->issue($oauth->name(), $redirectUri, $codeVerifier, $target->name(), $context);

        return [
            'state'             => $issued['state'],
            'authorization_url' => $oauth->getAuthorizationUrl(
                $issued['state'],
                $issued['nonce'],
                rest_url(DeviceAuthController::NAMESPACE . '/auth/callback'),
                $issued['code_verifier'],
            ),
        ];
    }

    /**
     * Spend a one-time code issued to $audience. Null for an unknown,
     * expired or already-used code, and for one issued to anyone else —
     * which is spent all the same.
     */
    public function redeem(string $code, string $audience): ?BrokeredIdentity
    {
        return $this->codes->redeem($code, $audience);
    }

    /**
     * The live Link enrolment a device token belongs to, or null.
     *
     * Null for anything Link itself would refuse: a malformed, unknown or
     * revoked token, or one whose member the gate no longer admits.
     */
    public function sessionFor(string $deviceToken): ?LinkSession
    {
        $device = $this->currentDevice->resolveToken($deviceToken)->device;
        if ($device === null) {
            return null;
        }

        $member = $this->gate->authorisedMember($device->memberEmail);
        if ($member === null) {
            return null;
        }

        return new LinkSession($device->id, $device->memberEmail, (int) $member->getId(), $device->platform);
    }

    /**
     * Whether a Link enrolment is still one Link would accept a request
     * from: the row exists, is not revoked, and its member is still
     * admitted. For a plugin that accepted {@see sessionFor()} once and
     * must stop when Link's enrolment stops.
     */
    public function isLive(int $deviceId): bool
    {
        if ($deviceId <= 0) {
            return false;
        }

        $device = $this->devices->findById($deviceId);
        if ($device === null || $device->isRevoked()) {
            return false;
        }

        return $this->gate->authorisedMember($device->memberEmail) !== null;
    }
}
