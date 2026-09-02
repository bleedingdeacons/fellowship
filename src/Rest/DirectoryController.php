<?php

declare(strict_types=1);

namespace Fellowship\Rest;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Directory\DirectoryPresenter;
use Scrutiny\Audit\Interfaces\AuditLogger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function add_action;
use function register_rest_route;

/**
 * The address book a handset shows when composing.
 *
 * <b>Audited, because it is a bulk exposure.</b> One directory call
 * hands over every listed member's anonymous name in a single response.
 * That is far less than their contact details — see
 * {@see DirectoryPresenter} — but it is still the whole membership in
 * one request, and Scrutiny should be able to answer "which handsets
 * pulled the directory, and when".
 *
 * The committee list is included only when sending to committees from
 * the app is enabled. Showing a list the app is not allowed to use would
 * be an invitation to a refusal.
 */
final class DirectoryController
{
    use RequiresSecureTransport;

    public const NAMESPACE = 'fellowship/v1';

    public function __construct(
        private readonly CurrentDevice $currentDevice,
        private readonly DirectoryPresenter $presenter,
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
        register_rest_route(self::NAMESPACE, '/directory', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'index'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function index(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($insecure = $this->insecureTransport()) {
            return $insecure;
        }

        $device = $this->currentDevice->fromRequest($request);
        if ($device === null) {
            return new WP_Error('fellowship_unauthenticated', 'This device is not signed in.', ['status' => 401]);
        }

        $directory = $this->presenter->forApp($this->settings->allowsCommitteeSendFromApp());

        $this->auditLogger->log(
            AuditLogger::ACTION_VIEW,
            AuditLogger::ENTITY_MEMBER,
            $device->memberId,
            'directory',
            'Link directory read;members:' . count($directory['members'])
                . ';committees:' . count($directory['committees'])
                . ';device:' . $device->id,
        );

        return new WP_REST_Response($directory, 200);
    }
}
