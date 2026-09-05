<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\Device;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\StubProvider;
use RuntimeException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;

/**
 * The two refusals every route on this controller shares.
 *
 * <b>HTTPS is a precondition, not a recommendation.</b> A bearer token
 * and an enrolment code both cross the wire on these routes, so a plain
 * request must be refused before it is answered rather than answered
 * with a warning — an app that got a working reply over http would
 * never be fixed. Twelve routes, and a route that forgot the check
 * would look exactly like one that has it until the day it mattered.
 *
 * <b>The rate limit is what stops the enrolment surface being a guessing
 * game.</b> It is reachable by anybody with the URL, so every route that
 * takes a credential counts the attempt rather than only the success;
 * asserting it per route is the only way to notice one that was added
 * without it.
 *
 * @covers \Fellowship\Rest\DeviceAuthController
 */
final class InsecureAndLimitedTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private InMemoryPasswordCredentialRepository $credentials;
    private DeviceTokenMinter $minter;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

        $this->devices = new InMemoryDeviceRepository();
        $this->credentials = new InMemoryPasswordCredentialRepository();
        $this->minter = new DeviceTokenMinter();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── Plain HTTP ────────────────────────────────────────────────────

    /**
     * @dataProvider routesThatRefusePlainHttp
     */
    public function testEveryRouteRefusesAPlainRequest(string $route): void
    {
        Functions\when('is_ssl')->justReturn(false);

        $controller = $this->controller();
        $token = $this->enrol();

        $response = $controller->{$route}($this->request(['email' => self::MEMBER], $token));

        self::assertInstanceOf(WP_Error::class, $response, $route . ' answered a plain request.');
        self::assertSame('fellowship_insecure_transport', $response->get_error_code(), $route . ' refused for the wrong reason.');
    }

    /** @return array<string, array{string}> */
    public static function routesThatRefusePlainHttp(): array
    {
        return [
            'start' => ['start'],
            'callback' => ['callback'],
            'password' => ['password'],
            'requestPassword' => ['requestPassword'],
            'completePassword' => ['completePassword'],
            'session' => ['session'],
        ];
    }

    // ── Too many attempts ─────────────────────────────────────────────

    /**
     * @dataProvider routesThatCountAttempts
     *
     * @param array<string, mixed> $params
     */
    public function testEveryCredentialRouteCountsTheAttempt(string $route, array $params): void
    {
        Functions\when('is_ssl')->justReturn(true);

        $controller = $this->controller();

        for ($i = 0; $i < 60; $i++) {
            $response = $controller->{$route}($this->request($params));

            if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
                self::assertTrue(true);

                return;
            }
        }

        self::fail($route . ' never rate-limited a repeated caller.');
    }

    /** @return array<string, array{string, array<string, mixed>}> */
    public static function routesThatCountAttempts(): array
    {
        return [
            'start' => ['start', ['provider' => 'google', 'redirect' => 'link://auth']],
            'password' => ['password', ['email' => self::MEMBER, 'password' => 'wrong', 'public_key' => 'spki', 'platform' => 'android']],
            'requestPassword' => ['requestPassword', ['email' => self::MEMBER]],
            'completePassword' => ['completePassword', ['token' => 'never-issued', 'password' => 'correct horse battery staple']],
        ];
    }

    // ── The rest ──────────────────────────────────────────────────────

    public function testTheControllerHooksItselfOntoTheRestApi(): void
    {
        // Routes registered anywhere but rest_api_init are routes that
        // exist on some requests and not others.
        Actions\expectAdded('rest_api_init')->once();

        $this->controller()->register();
    }

    public function testACallbackCarryingATargetThatIsNotTheAppIsRefused(): void
    {
        // The redirect carries a one-time code. It is validated again on
        // the way back rather than trusted from the state row, because a
        // state row is the one thing an attacker who reached this route
        // has already influenced.
        Functions\when('is_ssl')->justReturn(true);

        $issued = $this->stateStore()->issue('google', 'https://example.invalid/steal');

        $response = $this->controller()->callback($this->request([
            'state' => $issued['state'],
            'code' => 'a-code',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_redirect', $response->get_error_code());
    }

    public function testACallbackForAProviderThatIsNoLongerConfiguredSendsTheAppBack(): void
    {
        // Not a WP_Error: the app is mid-browser-leg and the only way to
        // tell it anything is through the redirect it is waiting on. It
        // happens when an admin removes a client id while somebody is
        // half way through signing in.
        Functions\when('is_ssl')->justReturn(true);

        $issued = $this->stateStore()->issue('microsoft', 'link://auth');

        $response = $this->controller()->callback($this->request([
            'state' => $issued['state'],
            'code' => 'a-code',
        ]));

        self::assertNotInstanceOf(WP_Error::class, $response);
    }

    public function testACallbackTheMemberDeclinedSendsTheAppBackToo(): void
    {
        Functions\when('is_ssl')->justReturn(true);

        $issued = $this->stateStore()->issue('google', 'link://auth');

        $response = $this->controller()->callback($this->request([
            'state' => $issued['state'],
            'error' => 'access_denied',
        ]));

        self::assertNotInstanceOf(WP_Error::class, $response);
    }

    public function testAHandsetThatCannotBeStoredIsFiveHundredRatherThanAFatal(): void
    {
        Functions\when('is_ssl')->justReturn(true);

        $issued = $this->stateStore()->issue('apple', '');

        $controller = $this->controller(
            new StubProvider('apple', serverSide: false),
            $this->throwingDevices(),
        );

        $response = $controller->exchange($this->request([
            'state' => $issued['state'],
            'id_token' => 'eyJ.header.sig',
            'public_key' => $this->publicKey(),
            'platform' => 'ios',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_enrolment_failed', $response->get_error_code());
    }

    public function testAKeyThatCannotBeStoredIsReportedRatherThanSilentlyDropped(): void
    {
        // Answering "ok" here would leave a handset holding a private
        // key the server has no public half for — it would receive
        // messages it could never open, indefinitely.
        Functions\when('is_ssl')->justReturn(true);

        $token = $this->enrol();
        $this->devices->rows = [];

        $response = $this->controller()->rotateKey($this->request(['public_key' => $this->publicKey()], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testUpdatingAPushTokenWithoutATokenIsRefused(): void
    {
        Functions\when('is_ssl')->justReturn(true);

        self::assertInstanceOf(
            WP_Error::class,
            $this->controller()->updatePush($this->request(['push_token' => 'fcm-2'])),
        );
    }

    public function testSigningOutWithoutATokenIsRefused(): void
    {
        Functions\when('is_ssl')->justReturn(true);

        self::assertInstanceOf(WP_Error::class, $this->controller()->signOut($this->request([])));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private StateStore $states;

    private function stateStore(): StateStore
    {
        return $this->states ??= new StateStore();
    }

    private function controller(
        ?StubProvider $provider = null,
        ?InMemoryDeviceRepository $devices = null,
    ): DeviceAuthController {
        $devices ??= $this->devices;
        $gate = new MemberGate($this->members);

        $registry = new ProviderRegistry();
        $registry->register($provider ?? new StubProvider('google', serverSide: true));

        return new DeviceAuthController(
            $devices,
            $this->minter,
            new DeviceCodeStore(),
            new DeviceRedirectValidator(),
            $gate,
            new CurrentDevice($devices, $this->minter, $gate, $this->members),
            $registry,
            $this->stateStore(),
            new RateLimiter(),
            new SpyAuditLogger(),
            new PasswordAuthenticator(
                $this->credentials,
                $gate,
                new PasswordResetMailer(),
                new PasswordPolicy(),
            ),
        );
    }

    private function throwingDevices(): InMemoryDeviceRepository
    {
        return new class extends InMemoryDeviceRepository {
            public function create(
                string $tokenHash,
                string $memberEmail,
                int $memberId,
                string $label,
                string $platform,
                string $publicKey,
                string $pushProvider,
                string $pushToken,
                int $now,
            ): Device {
                throw new RuntimeException('The devices table is gone.');
            }
        };
    }

    private function enrol(): string
    {
        $token = $this->minter->mint();

        $this->devices->create(
            $this->minter->hash($token),
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );

        return $token;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function request(array $params, string $token = ''): WP_REST_Request
    {
        $request = new WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        if ($token !== '') {
            $request->set_header('authorization', 'Bearer ' . $token);
        }

        return $request;
    }

    private function publicKey(): string
    {
        static $key = null;

        if ($key === null) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            if ($resource === false) {
                self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
            }

            $details = openssl_pkey_get_details($resource);
            self::assertIsArray($details);

            $key = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
        }

        return $key;
    }
}
