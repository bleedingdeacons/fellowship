<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
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
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Rest\DeviceAuthController
 * @covers \Fellowship\Rest\MessageController
 */
final class ControllerRoutesTest extends TestCase
{
    private const MEMBER = 'member@example.org';
    private const CALLBACK = 'link://auth';

    /** @var list<array{namespace: string, route: string}> */
    private array $routes = [];

    private InMemoryDeviceRepository $devices;
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryMemberRepository $members;
    private StateStore $states;
    private DeviceCodeStore $codes;
    private StubProvider $google;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);
        Functions\when('rest_url')->alias(
            static fn(string $p = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($p, '/')
        );

        $this->routes = [];
        Functions\when('register_rest_route')->alias(
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
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── The route table ───────────────────────────────────────────────

    public function testEveryAuthRouteIsRegistered(): void
    {
        $this->authController()->registerRoutes();

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
            self::assertContains($route, $registered, $route . ' is not registered.');
        }
    }

    public function testEveryMessageRouteIsRegistered(): void
    {
        $this->messageController()->registerRoutes();

        $registered = array_column($this->routes, 'route');

        self::assertContains('/messages', $registered);
    }

    public function testEveryRouteLivesUnderFellowshipsOwnNamespace(): void
    {
        // A route registered into another plugin's namespace would be
        // reachable at a URL the app never calls, and invisible at the
        // one it does.
        $this->authController()->registerRoutes();
        $this->messageController()->registerRoutes();

        foreach ($this->routes as $route) {
            self::assertSame('fellowship/v1', $route['namespace']);
        }
    }

    // ── The browser leg ───────────────────────────────────────────────

    public function testASuccessfulCallbackRedirectsWithAOneTimeCode(): void
    {
        // A code, never a token. The redirect passes through a browser,
        // where it lands in history and can be read by anything else
        // registered for the scheme.
        $issued = $this->states->issue('google', self::CALLBACK);

        $response = $this->authController()->callback($this->request([
            'state' => $issued['state'],
            'code' => 'from-google',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $location = (string) ($response->get_headers()['Location'] ?? '');
        self::assertStringStartsWith(self::CALLBACK, $location);
        self::assertStringContainsString('code=', $location);
        self::assertStringNotContainsString('token=', $location);
    }

    public function testAReplayedCallbackIsRefused(): void
    {
        // consume() is one-shot, so the second attempt finds nothing.
        $issued = $this->states->issue('google', self::CALLBACK);

        $first = $this->authController()->callback($this->request([
            'state' => $issued['state'],
            'code' => 'from-google',
        ]));
        self::assertInstanceOf(WP_REST_Response::class, $first);

        $second = $this->authController()->callback($this->request([
            'state' => $issued['state'],
            'code' => 'from-google',
        ]));

        self::assertInstanceOf(WP_Error::class, $second);
        self::assertSame('fellowship_bad_state', $second->get_error_code());
    }

    public function testAnInventedStateIsRefused(): void
    {
        $response = $this->authController()->callback($this->request(['state' => 'never-issued']));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_state', $response->get_error_code());
    }

    public function testDecliningAtTheProviderComesBackAsAReason(): void
    {
        // The member pressed cancel. They get a redirect saying so rather
        // than an error page in a browser tab they cannot act on.
        $issued = $this->states->issue('google', self::CALLBACK);

        $response = $this->authController()->callback($this->request([
            'state' => $issued['state'],
            'error' => 'access_denied',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertStringContainsString('error=declined', (string) ($response->get_headers()['Location'] ?? ''));
    }

    public function testAVerifiedAddressThatIsNotAMembersIsToldSoInTheBrowser(): void
    {
        // Checked here as well as at the exchange, so somebody who signed
        // in with the wrong Google account finds out where they can read
        // it rather than two steps later inside the app.
        $stranger = new StubProvider('google', serverSide: true);
        $stranger->identity = new VerifiedIdentity('nobody@example.org', 'google', 'sub-1');

        $issued = $this->states->issue('google', self::CALLBACK);

        $response = $this->authController($stranger)->callback($this->request([
            'state' => $issued['state'],
            'code' => 'from-google',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertStringContainsString('error=not_a_member', (string) ($response->get_headers()['Location'] ?? ''));
    }

    public function testAProviderThatCannotVerifyComesBackAsAReason(): void
    {
        $failing = new StubProvider('google', serverSide: true);
        $failing->identity = null;

        $issued = $this->states->issue('google', self::CALLBACK);

        $response = $this->authController($failing)->callback($this->request([
            'state' => $issued['state'],
            'code' => 'from-google',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertStringContainsString('error=verification', (string) ($response->get_headers()['Location'] ?? ''));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function authController(?StubProvider $provider = null): DeviceAuthController
    {
        $registry = new ProviderRegistry();
        $registry->register($provider ?? $this->google);

        $gate = new MemberGate($this->members);
        $minter = new DeviceTokenMinter();

        return new DeviceAuthController(
            $this->devices,
            $minter,
            $this->codes,
            new DeviceRedirectValidator(),
            $gate,
            new CurrentDevice($this->devices, $minter, $gate, $this->members),
            $registry,
            $this->states,
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

    private function messageController(): MessageController
    {
        $gate = new MemberGate($this->members);
        $settings = new Settings();
        $sealer = new MessageSealer();
        $minter = new DeviceTokenMinter();

        return new MessageController(
            new CurrentDevice($this->devices, $minter, $gate, $this->members),
            $this->messages,
            $this->recipients,
            new MessageDispatcher(
                $this->messages,
                $this->recipients,
                $this->devices,
                new FcmTransport(new FcmClient(), $settings, $sealer),
            ),
            new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
            $sealer,
            $this->members,
            $settings,
            new RateLimiter(),
            new SpyAuditLogger(),
        );
    }

    /**
     * @param array<string, string> $params
     */
    private function request(array $params): WP_REST_Request
    {
        $request = new WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        return $request;
    }
}
