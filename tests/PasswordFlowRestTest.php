<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
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
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
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
 */

covers(\Fellowship\Rest\DeviceAuthController::class);

const PASSWORD_FLOW_REST_MEMBER = 'member@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    $this->credentials = new InMemoryPasswordCredentialRepository();
    $this->devices = new InMemoryDeviceRepository();
    $this->mailer = new PasswordResetMailer();
    $this->audit = new SpyAuditLogger();
    $this->minter = new DeviceTokenMinter();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: PASSWORD_FLOW_REST_MEMBER),
    ]);
});

test('a code can be used to set a password', function () {
    $code = requestCode();

    $response = passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['ok'])->toBeTrue();
});

test('setting a password answers no session', function () {
    // Setting one and using one are separate acts, which is what
    // stops a code that reached the wrong handset from enrolling it.
    $code = requestCode();

    $response = passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect((array) $response->get_data())->not->toHaveKey('token');
});

test('setting a password is audited', function () {
    $code = requestCode();

    passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    expect($this->audit->entries)->not->toBeEmpty();
});

test('a weak password is refused and leaves the code usable', function () {
    // 422, not 400: the code was good, so it stays usable and the
    // member can try again without asking for another email.
    $code = requestCode();

    $rejected = passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'short',
    ]));

    expect($rejected)->toBeInstanceOf(WP_Error::class);
    expect($rejected->get_error_code())->toBe('fellowship_weak_password');

    $accepted = passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    expect($accepted)->toBeInstanceOf(WP_REST_Response::class);
});

test('the code is spent once it is used', function () {
    $code = requestCode();

    passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    $second = passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'a different passphrase entirely',
    ]));

    expect($second)->toBeInstanceOf(WP_Error::class);
});

test('the new password then signs in', function () {
    // The whole point of the flow, asserted end to end.
    $code = requestCode();

    passwordFlowRestController()->completePassword(passwordFlowRestRequest([
        'token' => $code,
        'password' => 'correct horse battery staple',
    ]));

    $response = passwordFlowRestController()->password(passwordFlowRestRequest([
        'email' => PASSWORD_FLOW_REST_MEMBER,
        'password' => 'correct horse battery staple',
        'public_key' => passwordFlowRestPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_status())->toBe(201);
});

// ── Rotating a key ────────────────────────────────────────────────

test('a key that will not load is refused', function () {
    // Storing it would leave a device that receives nothing and looks
    // perfectly healthy.
    //
    // Carries a credential because rotation needs one since
    // 2026-09-12 — this is about the key, so it has to get past the
    // gate in front of it.
    $token = passwordFlowRestEnrol();

    $response = passwordFlowRestController()->rotateKey(passwordFlowRestRequest(
        ['public_key' => 'not-a-key'] + passwordFlowRestCredential(),
        $token,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_public_key');
});

test('rotating a key for a handset that is gone is refused', function () {
    $token = passwordFlowRestEnrol();
    $this->devices->revoke(1, time());

    $response = passwordFlowRestController()->rotateKey(passwordFlowRestRequest(
        ['public_key' => passwordFlowRestPublicKey()] + passwordFlowRestCredential(),
        $token,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * A working password credential for the member, as the parameters a
 * request carries.
 *
 * @return array{email: string, password: string}
 */
function passwordFlowRestCredential(): array
{
    $password = 'correct horse battery staple';

    test()->credentials->upsertPasswordHash(
        PASSWORD_FLOW_REST_MEMBER,
        (string) password_hash($password, PASSWORD_DEFAULT),
        time(),
    );

    return ['email' => PASSWORD_FLOW_REST_MEMBER, 'password' => $password];
}

/** Ask for a code and read it back out of the email. */
function requestCode(): string
{
    $response = passwordFlowRestController()->requestPassword(passwordFlowRestRequest(['email' => PASSWORD_FLOW_REST_MEMBER]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    test()->mailer->flush();

    expect(WpState::$mail)->not->toBeEmpty('No code was emailed.');

    $body = (string) (WpState::$mail[count(WpState::$mail) - 1]['message'] ?? '');

    expect(preg_match('~^([A-Za-z0-9_-]{40,})$~m', $body, $matches))->toBe(1);

    return $matches[1];
}

function passwordFlowRestController(): DeviceAuthController
{
    $gate = new MemberGate(test()->members);

    $registry = new ProviderRegistry();
    $registry->register(new StubProvider('google', serverSide: true));

    return new DeviceAuthController(
        test()->devices,
        test()->minter,
        new DeviceCodeStore(),
        new DeviceRedirectValidator(),
        $gate,
        new CurrentDevice(test()->devices, test()->minter, $gate, test()->members),
        $registry,
        new StateStore(),
        new RateLimiter(),
        test()->audit,
        new PasswordAuthenticator(test()->credentials, $gate, test()->mailer, new PasswordPolicy()),
    );
}

function passwordFlowRestEnrol(): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        PASSWORD_FLOW_REST_MEMBER,
        7,
        'Pixel 6a',
        'android',
        passwordFlowRestPublicKey(),
        'fcm',
        'token-1',
        1788000000,
    );

    return $token;
}

/**
 * @param array<string, mixed> $params
 */
function passwordFlowRestRequest(array $params, string $token = ''): WP_REST_Request
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

function passwordFlowRestPublicKey(): string
{
    static $key = null;

    if ($key === null) {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $details = openssl_pkey_get_details($resource);
        expect($details)->toBeArray();

        $key = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }

    return $key;
}
