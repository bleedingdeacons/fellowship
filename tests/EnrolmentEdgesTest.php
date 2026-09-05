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
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\StubProvider;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The edges of enrolment: the wrong credential shape, the wrong flow, and
 * the limits.
 *
 * <b>Every refusal here answers the same way to a caller who is
 * guessing.</b> An expired code, a spent state, a token for a flow that
 * does not produce one — none of them says anything about whether an
 * address belongs to a member, because the whole point of the enrolment
 * surface is that it is reachable by anybody with the URL.
 *
 * <b>The rate limit is keyed on the caller's address.</b> It is what stops
 * a script working through addresses to find one the gate accepts, and it
 * has to count the attempt rather than only the success — otherwise
 * failing is free and only the last guess is charged for.
 *
 * @covers \Fellowship\Rest\DeviceAuthController
 */
final class EnrolmentEdgesTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private DeviceCodeStore $codes;
    private StateStore $states;
    private DeviceTokenMinter $minter;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

        $this->devices = new InMemoryDeviceRepository();
        $this->codes = new DeviceCodeStore();
        $this->states = new StateStore();
        $this->minter = new DeviceTokenMinter();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    public function testAnExchangeWithNoCredentialAtAllIsRefused(): void
    {
        $response = $this->controller()->exchange($this->request([
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_credential', $response->get_error_code());
    }

    public function testACodeNobodyIssuedIsRefused(): void
    {
        $response = $this->controller()->exchange($this->request([
            'code' => 'never-issued',
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_code', $response->get_error_code());
    }

    public function testAnIdTokenSentForABrowserProviderIsRefusedAsAWiringMistake(): void
    {
        // The app sent an ID token for a flow that does not produce one.
        // That is a mistake in the app rather than a failed sign-in, and
        // saying so plainly is what makes it findable.
        $issued = $this->states->issue('google', '');

        $response = $this->controller()->exchange($this->request([
            'state' => $issued['state'],
            'id_token' => 'eyJ.header.sig',
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_wrong_flow', $response->get_error_code());
    }

    public function testAnIdTokenAgainstASpentStateIsRefused(): void
    {
        $issued = $this->states->issue('apple', '');
        $this->states->consume($issued['state']);

        $response = $this->controller(new StubProvider('apple', serverSide: false))->exchange($this->request([
            'state' => $issued['state'],
            'id_token' => 'eyJ.header.sig',
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_state', $response->get_error_code());
    }

    public function testATokenTheProviderWillNotVerifyIsRefused(): void
    {
        $failing = new StubProvider('apple', serverSide: false);
        $failing->identity = null;

        $issued = $this->states->issue('apple', '');

        $response = $this->controller($failing)->exchange($this->request([
            'state' => $issued['state'],
            'id_token' => 'eyJ.header.sig',
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_id_token', $response->get_error_code());
    }

    public function testAClientSideTokenEnrolsWhenItVerifies(): void
    {
        // The Apple shape, all the way through.
        $issued = $this->states->issue('apple', '');

        $response = $this->controller(new StubProvider('apple', serverSide: false))->exchange($this->request([
            'state' => $issued['state'],
            'id_token' => 'eyJ.header.sig',
            'public_key' => $this->publicKey(),
            'platform' => 'ios',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(201, $response->get_status());
    }

    public function testTooManyAttemptsFromOneAddressAreRefused(): void
    {
        // What stops a script working through addresses to find one the
        // gate accepts. It counts the attempt rather than the success, so
        // failing is not free.
        $controller = $this->controller();

        for ($i = 0; $i < 40; $i++) {
            $response = $controller->exchange($this->request([
                'code' => 'never-issued',
                'public_key' => 'spki',
                'platform' => 'android',
            ]));

            if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
                self::assertTrue(true);

                return;
            }
        }

        self::fail('The enrolment endpoint never rate-limited a repeated caller.');
    }

    public function testAnEnrolledHandsetDescribesItselfBackToTheApp(): void
    {
        // The app renders this on its settings screen, so a member can
        // tell which handset they are looking at.
        $token = $this->enrol();

        $response = $this->controller()->session($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $data = (array) $response->get_data();

        self::assertSame('Pixel 6a', $data['device']['label']);
        self::assertSame('android', $data['device']['platform']);
        self::assertArrayNotHasKey('token', $data['device']);
    }

    public function testAPushRegistrationForAnUnknownTransportIsNormalised(): void
    {
        // Only fcm means push. Anything else has to become "no push"
        // rather than a stored value the dispatcher would later try to
        // deliver through.
        $token = $this->enrol();

        $this->controller()->updatePush($this->request([
            'push_provider' => 'carrier-pigeon',
            'push_token' => 'x',
        ], $token));

        self::assertNotSame('carrier-pigeon', $this->devices->rows[1]->pushProvider);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function controller(?StubProvider $provider = null): DeviceAuthController
    {
        $registry = new ProviderRegistry();
        $registry->register($provider ?? new StubProvider('google', serverSide: true));

        $gate = new MemberGate($this->members);

        return new DeviceAuthController(
            $this->devices,
            $this->minter,
            $this->codes,
            new DeviceRedirectValidator(),
            $gate,
            new CurrentDevice($this->devices, $this->minter, $gate, $this->members),
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

    private function enrol(): string
    {
        $code = $this->codes->issue(new VerifiedIdentity(self::MEMBER, 'google', 'sub-1'));

        $response = $this->controller()->exchange($this->request([
            'code' => $code,
            'public_key' => $this->publicKey(),
            'platform' => 'android',
            'label' => 'Pixel 6a',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        return (string) ((array) $response->get_data())['token'];
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
