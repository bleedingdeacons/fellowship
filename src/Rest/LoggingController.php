<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\DeviceResolution;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;

/**
 * Where an enrolled handset ships its logs, and what it authenticates
 * with.
 *
 * <b>Why the server hands this out rather than the app carrying it.</b>
 * A token built into Link is in every copy of the APK and IPA, readable
 * by anyone who unzips one, and changing it means a release. Handed out
 * here it reaches only a handset that has signed in as a member, can be
 * replaced or withdrawn from the settings screen, and is gone from a
 * handset the moment it signs out or is revoked — Link clears its copy
 * when its session ends.
 *
 * It does still end up on the handset. This moves the token out of the
 * binary; it does not make it a server-side secret. A Better Stack source
 * token can write to its source and cannot read from it, which is what
 * makes that an acceptable place for it.
 *
 * <b>Both fields or neither.</b> An endpoint with no token, or a token
 * with no endpoint, is answered as "not configured", so the app has only
 * two cases to handle: ship, or do not. Not audited: it is a setting, not
 * member data.
 */
final class LoggingController
{
    use RequiresSecureTransport;

    public const NAMESPACE = 'fellowship/v1';

    public function __construct(
        private readonly CurrentDevice $currentDevice,
        private readonly Settings $settings,
    ) {
    }

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/logging', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'show'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function show(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        $resolved = $this->currentDevice->resolve($request);
        if ($resolved->device === null) {
            return $resolved->refusal === DeviceResolution::NOT_A_MEMBER
                ? new WP_Error(
                    'fellowship_not_a_member',
                    'That address no longer matches a member record.',
                    ['status' => 403],
                )
                : new WP_Error('fellowship_unauthenticated', 'This device is not signed in.', ['status' => 401]);
        }

        $endpoint = $this->settings->getLogEndpoint();
        $token = $this->settings->getLogSourceToken();

        if ($endpoint === '' || $token === '') {
            $endpoint = '';
            $token = '';
        }

        $response = new WP_REST_Response(['endpoint' => $endpoint, 'source_token' => $token], 200);

        // A credential, so nothing between here and the handset keeps a
        // copy. WordPress only sends no-cache headers for a logged-in
        // user, and a device token is not one.
        $response->header('Cache-Control', 'no-store');

        return $response;
    }
}
