<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Rest\MessageController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\StubProvider;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The routes themselves, and the browser leg of a sign-in.
 *
 * <b>Registering a route is not a formality here.</b> Every one of these
 * is declared `permission_callback => '__return_true'` — deliberately,
 * because the bearer token is checked inside the handler and a WordPress
 * permission callback has no way to read it — so the route table is the
 * only place that says which HTTP verbs reach which method. A route
 * registered against the wrong callback, or with a required argument
 * missing, fails at the first handset rather than at boot.
 *
 * The browser callback is here because it is the one handler that never
 * answers a handset: it answers a *browser*, mid-redirect, and every
 * outcome is a redirect carrying a code or a reason. Getting one of those
 * wrong is a member staring at a tab that went nowhere.
 */

covers(\Fellowship\Rest\DeviceAuthController::class, \Fellowship\Rest\MessageController::class);

const CONTROLLER_ROUTES_MEMBER = 'member@example.org';

const CONTROLLER_ROUTES_CALLBACK = 'link://auth';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(
        static fn(string $p = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($p, '/')
    );

    $this->routes = [];
    when('register_rest_route')->alias(
        function (string $namespace, string $route, array $args = []): bool {
            $this->routes[] = ['namespace' => $namespace, 'route' => $route];

            return true;
        }
    );

    $this->devices = new InMemoryDeviceRepository();
    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->states = new StateStore();
    $this->codes = new DeviceCodeStore();
    $this->google = new StubProvider('google', serverSide: true);

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: CONTROLLER_ROUTES_MEMBER),
    ]);
});

// ── The route table ───────────────────────────────────────────────

test('every auth route is registered', function () {
    routesAuthController()->registerRoutes();

    $registered = array_column($this->routes, 'route');

    $expected = [
        '/auth/device/start',
        '/auth/callback',
        '/auth/device/exchange',
        '/auth/device/password',
        '/auth/password/request',
        '/auth/password/complete',
        '/auth/device/push',
        '/auth/device/key',
        '/auth/device/key-fault',
        '/auth/device/session',
        '/auth/device',
    ];

    foreach ($expected as $route) {
        expect($registered)->toContain($route);
    }
});

test('every message route is registered', function () {
    routesMessageController()->registerRoutes();

    $registered = array_column($this->routes, 'route');

    expect($registered)->toContain('/messages');
    expect($registered)->toContain('/messages/received');
    expect($registered)->toContain('/messages/receipts');
});

test('every route lives under fellowships own namespace', function () {
    // A route registered into another plugin's namespace would be
    // reachable at a URL the app never calls, and invisible at the
    // one it does.
    routesAuthController()->registerRoutes();
    routesMessageController()->registerRoutes();

    foreach ($this->routes as $route) {
        expect($route['namespace'])->toBe('fellowship/v1');
    }
});

// ── The browser leg ───────────────────────────────────────────────

test('a successful callback redirects with a one time code', function () {
    // A code, never a token. The redirect passes through a browser,
    // where it lands in history and can be read by anything else
    // registered for the scheme.
    $issued = $this->states->issue('google', CONTROLLER_ROUTES_CALLBACK);

    $response = routesAuthController()->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'code' => 'from-google',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $location = (string) ($response->get_headers()['Location'] ?? '');
    expect($location)->toStartWith(CONTROLLER_ROUTES_CALLBACK);
    expect($location)->toContain('code=');
    expect($location)->not->toContain('token=');
});

test('a replayed callback is refused', function () {
    // consume() is one-shot, so the second attempt finds nothing.
    $issued = $this->states->issue('google', CONTROLLER_ROUTES_CALLBACK);

    $first = routesAuthController()->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'code' => 'from-google',
    ]));
    expect($first)->toBeInstanceOf(WP_REST_Response::class);

    $second = routesAuthController()->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'code' => 'from-google',
    ]));

    expect($second)->toBeInstanceOf(WP_Error::class);
    expect($second->get_error_code())->toBe('fellowship_bad_state');
});

test('an invented state is refused', function () {
    $response = routesAuthController()->callback(controllerRoutesRequest(['state' => 'never-issued']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_state');
});

test('declining at the provider comes back as a reason', function () {
    // The member pressed cancel. They get a redirect saying so rather
    // than an error page in a browser tab they cannot act on.
    $issued = $this->states->issue('google', CONTROLLER_ROUTES_CALLBACK);

    $response = routesAuthController()->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'error' => 'access_denied',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect((string) ($response->get_headers()['Location'] ?? ''))->toContain('error=declined');
});

test('a verified address that is not a members is told so in the browser', function () {
    // Checked here as well as at the exchange, so somebody who signed
    // in with the wrong Google account finds out where they can read
    // it rather than two steps later inside the app.
    $stranger = new StubProvider('google', serverSide: true);
    $stranger->identity = new VerifiedIdentity('nobody@example.org', 'google', 'sub-1');

    $issued = $this->states->issue('google', CONTROLLER_ROUTES_CALLBACK);

    $response = routesAuthController($stranger)->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'code' => 'from-google',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect((string) ($response->get_headers()['Location'] ?? ''))->toContain('error=not_a_member');
});

test('a provider that cannot verify comes back as a reason', function () {
    $failing = new StubProvider('google', serverSide: true);
    $failing->identity = null;

    $issued = $this->states->issue('google', CONTROLLER_ROUTES_CALLBACK);

    $response = routesAuthController($failing)->callback(controllerRoutesRequest([
        'state' => $issued['state'],
        'code' => 'from-google',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect((string) ($response->get_headers()['Location'] ?? ''))->toContain('error=verification');
});

// ── Fixtures ──────────────────────────────────────────────────────

function routesAuthController(?StubProvider $provider = null): DeviceAuthController
{
    $registry = new ProviderRegistry();
    $registry->register($provider ?? test()->google);

    $gate = new MemberGate(test()->members);
    $minter = new DeviceTokenMinter();

    return new DeviceAuthController(
        test()->devices,
        $minter,
        test()->codes,
        new DeviceRedirectValidator(),
        $gate,
        new CurrentDevice(test()->devices, $minter, $gate, test()->members),
        $registry,
        test()->states,
        new RateLimiter(),
        new SpyAuditLogger(),
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
    );
}

function routesMessageController(): MessageController
{
    $gate = new MemberGate(test()->members);
    $settings = new Settings();
    $sealer = new MessageSealer();
    $minter = new DeviceTokenMinter();

    return new MessageController(
        new CurrentDevice(test()->devices, $minter, $gate, test()->members),
        test()->messages,
        test()->recipients,
        new MessageDispatcher(
            test()->messages,
            test()->recipients,
            test()->devices,
            new FcmTransport(new FcmClient(), $settings, $sealer),
        ),
        new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
        $sealer,
        test()->members,
        $settings,
        new RateLimiter(),
        new SpyAuditLogger(),
    );
}

/**
 * @param array<string, string> $params
 */
function controllerRoutesRequest(array $params): WP_REST_Request
{
    $request = new WP_REST_Request();

    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }

    return $request;
}
