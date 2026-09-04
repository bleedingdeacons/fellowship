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
use Fellowship\Auth\Providers\OAuthProvider;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The enrolment surface: every way a handset gets a token, and every way
 * it is refused one.
 *
 * <b>This controller is the plugin's front door and the largest single
 * thing in it.</b> Everything behind it — the message log, the device
 * list, the sealed payloads — assumes the caller is a member's handset,
 * and this is the only code that decides so.
 *
 * The refusals matter more than the successes and are what most of this
 * file asserts. Three in particular are easy to break without any test
 * failing: the device cap, the shared enrolment path (so a password
 * sign-in cannot skip a check the OAuth one makes), and the fact that a
 * revoked device is refused because it can no longer be found rather
 * than because anything downstream inspects a flag.
 *
 * HTTPS is stubbed on throughout. Every route refuses plain HTTP, which
 * is asserted once rather than in each test.
 *
 * @covers \Fellowship\Rest\DeviceAuthController
 */
final class DeviceAuthControllerTest extends TestCase
{
    private const MEMBER = 'member@example.org';
    private const CALLBACK = 'link://auth';

    private InMemoryDeviceRepository $devices;
    private InMemoryPasswordCredentialRepository $credentials;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;
    private DeviceTokenMinter $minter;
    private StateStore $states;
    private DeviceCodeStore $codes;
    private StubProvider $google;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);
        Functions\when('rest_url')->alias(
            static fn(string $path = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($path, '/')
        );

        $this->devices = new InMemoryDeviceRepository();
        $this->credentials = new InMemoryPasswordCredentialRepository();
        $this->audit = new SpyAuditLogger();
        $this->minter = new DeviceTokenMinter();
        $this->states = new StateStore();
        $this->codes = new DeviceCodeStore();
        $this->google = new StubProvider('google', serverSide: true);

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── Starting a sign-in ────────────────────────────────────────────

    public function testAStartForABrowserProviderAnswersAUrlAndAState(): void
    {
        $response = $this->controller()->start($this->request(['provider' => 'google', 'redirect_uri' => self::CALLBACK]));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $data = (array) $response->get_data();
        self::assertNotSame('', $data['state']);
        self::assertStringContainsString('https://', (string) $data['authorization_url']);
    }

    public function testAStartForAClientSideProviderAnswersANonceInstead(): void
    {
        // Apple's shape. There is no browser leg, so a nonce goes to the
        // app to put into the platform sheet and no URL is issued.
        $response = $this->controller(new StubProvider('apple', serverSide: false))
            ->start($this->request(['provider' => 'apple']));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $data = (array) $response->get_data();
        self::assertNotSame('', $data['nonce']);
        self::assertArrayNotHasKey('authorization_url', $data);
    }

    public function testAnUnknownProviderIsRefused(): void
    {
        $response = $this->controller()->start($this->request(['provider' => 'myspace']));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_unknown_provider', $response->get_error_code());
    }

    public function testARedirectOutsideTheAllowListIsRefused(): void
    {
        // The one-time code comes back through this URI. Accepting an
        // arbitrary one would hand the code to whoever asked.
        $response = $this->controller()->start($this->request([
            'provider' => 'google',
            'redirect_uri' => 'https://example.invalid/steal',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_redirect', $response->get_error_code());
    }

    public function testPlainHttpIsRefusedOnEveryRoute(): void
    {
        // Asserted once, on the route that would leak the most: the
        // exchange carries the credential.
        Functions\when('is_ssl')->justReturn(false);

        $response = $this->controller()->exchange($this->request([]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_insecure_transport', $response->get_error_code());
    }

    // ── Exchanging a credential for a token ───────────────────────────

    public function testAVerifiedIdentityEnrolsAndYieldsAToken(): void
    {
        $response = $this->controller()->exchange($this->exchangeRequest());

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(201, $response->get_status());

        $data = (array) $response->get_data();
        self::assertNotSame('', $data['token']);
        self::assertSame(7, $data['member']['id']);

        // The raw token exists here and nowhere else — the row holds an
        // HMAC — so an app that loses it must enrol again.
        self::assertCount(1, $this->devices->rows);
    }

    public function testEnrolmentIsAudited(): void
    {
        $this->controller()->exchange($this->exchangeRequest());

        self::assertNotEmpty($this->audit->entries);
    }

    public function testAnAddressThatIsNotAMembersIsRefused(): void
    {
        $code = $this->codes->issue(new VerifiedIdentity('nobody@example.org', 'google', 'sub-1'));

        $response = $this->controller()->exchange($this->request([
            'code' => $code,
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_not_a_member', $response->get_error_code());
        self::assertSame([], $this->devices->rows);
    }

    public function testAnUnreadablePublicKeyFailsEnrolment(): void
    {
        // Validated before anything is written: a key that will not load
        // must fail here rather than become a device that silently
        // receives nothing.
        $response = $this->controller()->exchange($this->exchangeRequest(['public_key' => 'not-a-key']));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_public_key', $response->get_error_code());
    }

    public function testAnUnrecognisedPlatformIsRefused(): void
    {
        $response = $this->controller()->exchange($this->exchangeRequest(['platform' => 'blackberry']));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_platform', $response->get_error_code());
    }

    public function testAMemberCannotEnrolMoreThanTheCap(): void
    {
        // Without this a lost handset is never noticed, because there is
        // always room for one more.
        for ($i = 0; $i < $this->cap(); $i++) {
            $response = $this->controller()->exchange($this->exchangeRequest());
            self::assertInstanceOf(WP_REST_Response::class, $response);
        }

        $refused = $this->controller()->exchange($this->exchangeRequest());

        self::assertInstanceOf(WP_Error::class, $refused);
        self::assertSame('fellowship_too_many_devices', $refused->get_error_code());
    }

    public function testARevokedDeviceDoesNotCountTowardsTheCap(): void
    {
        // Otherwise a member who loses a phone can never replace it.
        for ($i = 0; $i < $this->cap(); $i++) {
            $this->controller()->exchange($this->exchangeRequest());
        }

        $this->devices->revoke(1, time());

        self::assertInstanceOf(WP_REST_Response::class, $this->controller()->exchange($this->exchangeRequest()));
    }

    // ── Password sign-in ──────────────────────────────────────────────

    public function testAPasswordSignInEnrolsThroughTheSamePath(): void
    {
        // The point of sharing enrolVerified: a password sign-in must not
        // skip a check the OAuth one makes.
        $this->givenPassword('correct horse battery staple');

        $response = $this->controller()->password($this->request([
            'email' => self::MEMBER,
            'password' => 'correct horse battery staple',
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(201, $response->get_status());
    }

    public function testAPasswordSignInObeysTheSameDeviceCap(): void
    {
        $this->givenPassword('correct horse battery staple');

        for ($i = 0; $i < $this->cap(); $i++) {
            $this->controller()->exchange($this->exchangeRequest());
        }

        $response = $this->controller()->password($this->request([
            'email' => self::MEMBER,
            'password' => 'correct horse battery staple',
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_too_many_devices', $response->get_error_code());
    }

    public function testAWrongPasswordIsOneMessageForEveryCause(): void
    {
        // Unknown address, no password set, wrong password and locked
        // account all answer this. Telling them apart would say which
        // addresses belong to members.
        $this->givenPassword('correct horse battery staple');

        $response = $this->controller()->password($this->request([
            'email' => self::MEMBER,
            'password' => 'wrong',
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_credentials', $response->get_error_code());
    }

    public function testAnAddressWithNoPasswordAnswersTheSameThing(): void
    {
        $response = $this->controller()->password($this->request([
            'email' => self::MEMBER,
            'password' => 'anything',
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_credentials', $response->get_error_code());
    }

    // ── Asking for, and setting, a password ───────────────────────────

    public function testRequestingACodeAnswersTheSameForAMemberAndAStranger(): void
    {
        $forMember = $this->controller()->requestPassword($this->request(['email' => self::MEMBER]));
        $forStranger = $this->controller()->requestPassword($this->request(['email' => 'nobody@example.org']));

        self::assertInstanceOf(WP_REST_Response::class, $forMember);
        self::assertInstanceOf(WP_REST_Response::class, $forStranger);
        self::assertSame($forMember->get_status(), $forStranger->get_status());
        self::assertSame($forMember->get_data(), $forStranger->get_data());
    }

    public function testASpentCodeIsRefused(): void
    {
        $response = $this->controller()->completePassword($this->request([
            'token' => 'a-code-nobody-issued',
            'password' => 'a perfectly good passphrase',
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_reset_token', $response->get_error_code());
    }

    // ── What an enrolled handset may do ───────────────────────────────

    public function testAnEnrolledHandsetCanRegisterAPushToken(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->updatePush($this->request(
            ['push_provider' => 'fcm', 'push_token' => 'fcm-1'],
            $token,
        ));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame('fcm-1', $this->devices->rows[1]->pushToken);
    }

    public function testARotatedKeyReplacesTheStoredOneAndClearsTheFault(): void
    {
        $token = $this->enrol();
        $this->devices->markKeyFault(1, time());

        $response = $this->controller()->rotateKey($this->request(['public_key' => $this->publicKey()], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertFalse($this->devices->rows[1]->hasKeyFault());
    }

    public function testAKeyFaultIsRecorded(): void
    {
        // The server cannot infer this: a handset with a lost private key
        // looks perfectly healthy until a message it cannot read.
        $token = $this->enrol();

        $response = $this->controller()->reportKeyFault($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertTrue($this->devices->rows[1]->hasKeyFault());
    }

    public function testTheSessionRouteDescribesTheCallingHandset(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->session($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(7, ((array) $response->get_data())['member']['id']);
    }

    public function testSigningOutRevokesTheDevice(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->signOut($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertTrue($this->devices->rows[1]->isRevoked());
    }

    public function testARevokedHandsetIsRefusedEverywhere(): void
    {
        // Refused because it can no longer be found, not because anything
        // downstream checks a flag. That is the whole mechanism.
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        foreach (['session', 'reportKeyFault'] as $route) {
            $response = $this->controller()->{$route}($this->request([], $token));
            self::assertInstanceOf(WP_Error::class, $response, $route . ' accepted a revoked device.');
        }
    }

    public function testAnUnauthenticatedRequestIsRefused(): void
    {
        $response = $this->controller()->session($this->request([]));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testAnInventedTokenIsRefused(): void
    {
        $response = $this->controller()->session($this->request([], 'fdt_' . str_repeat('a', 40)));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /**
     * The device cap, read from the controller rather than restated.
     *
     * A test carrying its own copy of 5 goes on passing when the cap
     * moves, and stops testing the cap.
     */
    private function cap(): int
    {
        $constant = new \ReflectionClassConstant(DeviceAuthController::class, 'MAX_DEVICES_PER_MEMBER');

        return (int) $constant->getValue();
    }

    private function controller(?OAuthProvider $provider = null): DeviceAuthController
    {
        $provider ??= $this->google;

        $registry = new ProviderRegistry();
        $registry->register($provider);

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
            $this->audit,
            new PasswordAuthenticator(
                $this->credentials,
                $gate,
                new PasswordResetMailer(),
                new PasswordPolicy(),
            ),
        );
    }

    /**
     * Enrol a handset and answer its bearer token.
     */
    private function enrol(): string
    {
        $response = $this->controller()->exchange($this->exchangeRequest());
        self::assertInstanceOf(WP_REST_Response::class, $response);

        return (string) ((array) $response->get_data())['token'];
    }

    /**
     * An exchange request carrying a code the stub provider will verify.
     *
     * @param array<string, string> $overrides
     */
    private function exchangeRequest(array $overrides = []): WP_REST_Request
    {
        $issued = $this->codes->issue(new VerifiedIdentity(self::MEMBER, 'google', 'sub-1'));

        return $this->request(array_merge([
            'code' => $issued,
            'public_key' => $this->publicKey(),
            'platform' => 'android',
            'label' => 'Pixel 6a',
        ], $overrides));
    }

    /**
     * @param array<string, string> $params
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

    private function givenPassword(string $password): void
    {
        $this->credentials->upsertPasswordHash(
            self::MEMBER,
            (string) password_hash($password, PASSWORD_DEFAULT),
            time(),
        );
    }

    /**
     * A real RSA-2048 public key, base64 SPKI — what a handset sends.
     */
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

/**
 * A provider that verifies whatever it is given.
 *
 * The provider implementations have their own tests; what this controller
 * needs is something that answers a known identity so the tests are about
 * enrolment rather than about JWKS.
 */
final class StubProvider implements OAuthProvider
{
    public ?VerifiedIdentity $identity = null;

    public function __construct(
        private readonly string $name,
        private readonly bool $serverSide,
    ) {
        $this->identity = new VerifiedIdentity('member@example.org', $name, 'sub-1');
    }

    public function name(): string
    {
        return $this->name;
    }

    public function isServerSide(): bool
    {
        return $this->serverSide;
    }

    public function requiresPkce(): bool
    {
        return false;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        return 'https://accounts.example.org/authorize?state=' . $state;
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        return $this->identity;
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        return $this->identity;
    }
}
