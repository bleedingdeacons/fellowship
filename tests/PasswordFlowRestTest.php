<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
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
 * The password endpoints, end to end through the REST surface.
 *
 * <b>Setting a password is deliberately not signing in.</b> The endpoint
 * answers no session, so a code that reaches the wrong handset cannot
 * enrol it — the member goes back to the sign-in screen and uses the
 * password they just chose.
 *
 * <b>A weak password is 422, not 400</b>, and the difference is not
 * pedantry: the request was well formed and the code was good, so the
 * code stays usable and the member can try a different password without
 * asking for another email. A 400 would suggest the link was the problem.
 *
 * @covers \Fellowship\Rest\DeviceAuthController
 */
final class PasswordFlowRestTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryPasswordCredentialRepository $credentials;
    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private PasswordResetMailer $mailer;
    private SpyAuditLogger $audit;
    private DeviceTokenMinter $minter;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        $this->credentials = new InMemoryPasswordCredentialRepository();
        $this->devices = new InMemoryDeviceRepository();
        $this->mailer = new PasswordResetMailer();
        $this->audit = new SpyAuditLogger();
        $this->minter = new DeviceTokenMinter();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    public function testACodeCanBeUsedToSetAPassword(): void
    {
        $code = $this->requestCode();

        $response = $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertTrue(((array) $response->get_data())['ok']);
    }

    public function testSettingAPasswordAnswersNoSession(): void
    {
        // Setting one and using one are separate acts, which is what
        // stops a code that reached the wrong handset from enrolling it.
        $code = $this->requestCode();

        $response = $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertArrayNotHasKey('token', (array) $response->get_data());
    }

    public function testSettingAPasswordIsAudited(): void
    {
        $code = $this->requestCode();

        $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        self::assertNotEmpty($this->audit->entries);
    }

    public function testAWeakPasswordIsRefusedAndLeavesTheCodeUsable(): void
    {
        // 422, not 400: the code was good, so it stays usable and the
        // member can try again without asking for another email.
        $code = $this->requestCode();

        $rejected = $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'short',
        ]));

        self::assertInstanceOf(WP_Error::class, $rejected);
        self::assertSame('fellowship_weak_password', $rejected->get_error_code());

        $accepted = $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $accepted);
    }

    public function testTheCodeIsSpentOnceItIsUsed(): void
    {
        $code = $this->requestCode();

        $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        $second = $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'a different passphrase entirely',
        ]));

        self::assertInstanceOf(WP_Error::class, $second);
    }

    public function testTheNewPasswordThenSignsIn(): void
    {
        // The whole point of the flow, asserted end to end.
        $code = $this->requestCode();

        $this->controller()->completePassword($this->request([
            'token' => $code,
            'password' => 'correct horse battery staple',
        ]));

        $response = $this->controller()->password($this->request([
            'email' => self::MEMBER,
            'password' => 'correct horse battery staple',
            'public_key' => $this->publicKey(),
            'platform' => 'android',
        ]));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(201, $response->get_status());
    }

    // ── Rotating a key ────────────────────────────────────────────────

    public function testAKeyThatWillNotLoadIsRefused(): void
    {
        // Storing it would leave a device that receives nothing and looks
        // perfectly healthy.
        $token = $this->enrol();

        $response = $this->controller()->rotateKey($this->request(['public_key' => 'not-a-key'], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_bad_public_key', $response->get_error_code());
    }

    public function testRotatingAKeyForAHandsetThatIsGoneIsRefused(): void
    {
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        self::assertInstanceOf(
            WP_Error::class,
            $this->controller()->rotateKey($this->request(['public_key' => $this->publicKey()], $token)),
        );
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /** Ask for a code and read it back out of the email. */
    private function requestCode(): string
    {
        $response = $this->controller()->requestPassword($this->request(['email' => self::MEMBER]));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $this->mailer->flush();

        self::assertNotEmpty(WpState::$mail, 'No code was emailed.');

        $body = (string) (WpState::$mail[count(WpState::$mail) - 1]['message'] ?? '');

        self::assertSame(1, preg_match('~^([A-Za-z0-9_-]{40,})$~m', $body, $matches));

        return $matches[1];
    }

    private function controller(): DeviceAuthController
    {
        $gate = new MemberGate($this->members);

        $registry = new ProviderRegistry();
        $registry->register(new StubProvider('google', serverSide: true));

        return new DeviceAuthController(
            $this->devices,
            $this->minter,
            new DeviceCodeStore(),
            new DeviceRedirectValidator(),
            $gate,
            new CurrentDevice($this->devices, $this->minter, $gate, $this->members),
            $registry,
            new StateStore(),
            new RateLimiter(),
            $this->audit,
            new PasswordAuthenticator($this->credentials, $gate, $this->mailer, new PasswordPolicy()),
        );
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
            $this->publicKey(),
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
