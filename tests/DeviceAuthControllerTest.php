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
use Fellowship\Auth\Providers\OAuthProvider;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\StubProvider;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
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
 */

covers(\Fellowship\Rest\DeviceAuthController::class);

const DEVICE_AUTH_CONTROLLER_MEMBER = 'member@example.org';

/** A second member, for the "not your handset" case. */
const DEVICE_AUTH_CONTROLLER_OTHER = 'other@example.org';

const DEVICE_AUTH_CONTROLLER_CALLBACK = 'link://auth';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(
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
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: DEVICE_AUTH_CONTROLLER_MEMBER),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: DEVICE_AUTH_CONTROLLER_OTHER),
    ]);
});

// ── Starting a sign-in ────────────────────────────────────────────

test('a start for a browser provider answers a URL and a state', function () {
    $response = deviceAuthControllerController()->start(deviceAuthControllerRequest(['provider' => 'google', 'redirect_uri' => DEVICE_AUTH_CONTROLLER_CALLBACK]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $data = (array) $response->get_data();
    expect($data['state'])->not->toBe('');
    expect((string) $data['authorization_url'])->toContain('https://');
});

test('a start for a client side provider answers a nonce instead', function () {
    // Apple's shape. There is no browser leg, so a nonce goes to the
    // app to put into the platform sheet and no URL is issued.
    $response = deviceAuthControllerController(new StubProvider('apple', serverSide: false))
        ->start(deviceAuthControllerRequest(['provider' => 'apple']));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $data = (array) $response->get_data();
    expect($data['nonce'])->not->toBe('');
    expect($data)->not->toHaveKey('authorization_url');
});

test('an unknown provider is refused', function () {
    $response = deviceAuthControllerController()->start(deviceAuthControllerRequest(['provider' => 'myspace']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unknown_provider');
});

test('a redirect outside the allow list is refused', function () {
    // The one-time code comes back through this URI. Accepting an
    // arbitrary one would hand the code to whoever asked.
    $response = deviceAuthControllerController()->start(deviceAuthControllerRequest([
        'provider' => 'google',
        'redirect_uri' => 'https://example.invalid/steal',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_redirect');
});

test('plain HTTP is refused on every route', function () {
    // Asserted once, on the route that would leak the most: the
    // exchange carries the credential.
    when('is_ssl')->justReturn(false);

    $response = deviceAuthControllerController()->exchange(deviceAuthControllerRequest([]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_insecure_transport');
});

// ── Exchanging a credential for a token ───────────────────────────

test('a verified identity enrols and yields a token', function () {
    $response = deviceAuthControllerController()->exchange(exchangeRequest());

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_status())->toBe(201);

    $data = (array) $response->get_data();
    expect($data['token'])->not->toBe('');
    expect($data['member']['id'])->toBe(7);

    // The raw token exists here and nowhere else — the row holds an
    // HMAC — so an app that loses it must enrol again.
    expect($this->devices->rows)->toHaveCount(1);
});

test('enrolment is audited', function () {
    deviceAuthControllerController()->exchange(exchangeRequest());

    expect($this->audit->entries)->not->toBeEmpty();
});

test('an address that is not a members is refused', function () {
    $code = $this->codes->issue(new VerifiedIdentity('nobody@example.org', 'google', 'sub-1'));

    $response = deviceAuthControllerController()->exchange(deviceAuthControllerRequest([
        'code' => $code,
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_not_a_member');
    expect($this->devices->rows)->toBe([]);
});

test('an unreadable public key fails enrolment', function () {
    // Validated before anything is written: a key that will not load
    // must fail here rather than become a device that silently
    // receives nothing.
    $response = deviceAuthControllerController()->exchange(exchangeRequest(['public_key' => 'not-a-key']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_public_key');
});

test('an unrecognised platform is refused', function () {
    $response = deviceAuthControllerController()->exchange(exchangeRequest(['platform' => 'blackberry']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_platform');
});

test('a member cannot enrol more than the cap', function () {
    // Without this a lost handset is never noticed, because there is
    // always room for one more.
    for ($i = 0; $i < deviceAuthControllerCap(); $i++) {
        $response = deviceAuthControllerController()->exchange(exchangeRequest());
        expect($response)->toBeInstanceOf(WP_REST_Response::class);
    }

    $refused = deviceAuthControllerController()->exchange(exchangeRequest());

    expect($refused)->toBeInstanceOf(WP_Error::class);
    expect($refused->get_error_code())->toBe('fellowship_too_many_devices');
});

test('a revoked device does not count towards the cap', function () {
    // Otherwise a member who loses a phone can never replace it.
    for ($i = 0; $i < deviceAuthControllerCap(); $i++) {
        deviceAuthControllerController()->exchange(exchangeRequest());
    }

    $this->devices->revoke(1, time());

    expect(deviceAuthControllerController()->exchange(exchangeRequest()))->toBeInstanceOf(WP_REST_Response::class);
});

// ── Password sign-in ──────────────────────────────────────────────

test('a password sign in enrols through the same path', function () {
    // The point of sharing enrolVerified: a password sign-in must not
    // skip a check the OAuth one makes.
    deviceAuthControllerGivenPassword('correct horse battery staple');

    $response = deviceAuthControllerController()->password(deviceAuthControllerRequest([
        'email' => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password' => 'correct horse battery staple',
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_status())->toBe(201);
});

test('a password sign in obeys the same device cap', function () {
    deviceAuthControllerGivenPassword('correct horse battery staple');

    for ($i = 0; $i < deviceAuthControllerCap(); $i++) {
        deviceAuthControllerController()->exchange(exchangeRequest());
    }

    $response = deviceAuthControllerController()->password(deviceAuthControllerRequest([
        'email' => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password' => 'correct horse battery staple',
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_too_many_devices');
});

test('a wrong password is one message for every cause', function () {
    // Unknown address, no password set, wrong password and locked
    // account all answer this. Telling them apart would say which
    // addresses belong to members.
    deviceAuthControllerGivenPassword('correct horse battery staple');

    $response = deviceAuthControllerController()->password(deviceAuthControllerRequest([
        'email' => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password' => 'wrong',
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_credentials');
});

test('an address with no password answers the same thing', function () {
    $response = deviceAuthControllerController()->password(deviceAuthControllerRequest([
        'email' => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password' => 'anything',
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_credentials');
});

// ── Asking for, and setting, a password ───────────────────────────

test('requesting a code answers the same for a member and a stranger', function () {
    $forMember = deviceAuthControllerController()->requestPassword(deviceAuthControllerRequest(['email' => DEVICE_AUTH_CONTROLLER_MEMBER]));
    $forStranger = deviceAuthControllerController()->requestPassword(deviceAuthControllerRequest(['email' => 'nobody@example.org']));

    expect($forMember)->toBeInstanceOf(WP_REST_Response::class);
    expect($forStranger)->toBeInstanceOf(WP_REST_Response::class);
    expect($forStranger->get_status())->toBe($forMember->get_status());
    expect($forStranger->get_data())->toBe($forMember->get_data());
});

test('a spent code is refused', function () {
    $response = deviceAuthControllerController()->completePassword(deviceAuthControllerRequest([
        'token' => 'a-code-nobody-issued',
        'password' => 'a perfectly good passphrase',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_reset_token');
});

// ── What an enrolled handset may do ───────────────────────────────

test('an enrolled handset can register a push token', function () {
    $token = deviceAuthControllerEnrol();

    $response = deviceAuthControllerController()->updatePush(deviceAuthControllerRequest(
        ['push_provider' => 'fcm', 'push_token' => 'fcm-1'],
        $token,
    ));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->devices->rows[1]->pushToken)->toBe('fcm-1');
});

test('a rotated key replaces the stored one and clears the fault', function () {
    $token = deviceAuthControllerEnrol();
    $this->devices->markKeyFault(1, time());
    deviceAuthControllerGivenPassword('correct horse battery staple');

    $response = deviceAuthControllerController()->rotateKey(deviceAuthControllerRequest([
        'public_key' => deviceAuthControllerPublicKey(),
        'email'      => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password'   => 'correct horse battery staple',
    ], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->devices->rows[1]->hasKeyFault())->toBeFalse();
});

/**
 * The point of the whole change. Substituting the key is enough to
 * have every retained message re-sealed to it, so a captured bearer
 * token on its own must not be able to do it.
 */
test('a token alone no longer rotates a key', function () {
    $token = deviceAuthControllerEnrol();
    $before = $this->devices->rows[1]->publicKey;

    $response = deviceAuthControllerController()->rotateKey(deviceAuthControllerRequest(['public_key' => deviceAuthControllerPublicKey()], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_credential');
    expect($this->devices->rows[1]->publicKey)->toBe($before);
});

test('a wrong password does not rotate a key', function () {
    $token = deviceAuthControllerEnrol();
    deviceAuthControllerGivenPassword('correct horse battery staple');
    $before = $this->devices->rows[1]->publicKey;

    $response = deviceAuthControllerController()->rotateKey(deviceAuthControllerRequest([
        'public_key' => deviceAuthControllerPublicKey(),
        'email'      => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password'   => 'wrong',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_credentials');
    expect($this->devices->rows[1]->publicKey)->toBe($before);
});

/**
 * Proving your own identity does not let you rotate somebody else's
 * key. Without this check the attack simply puts on a hat: capture a
 * token, sign in as yourself, substitute the key on their handset.
 */
test('a credential for another member does not rotate this key', function () {
    $token = deviceAuthControllerEnrol();
    $this->credentials->upsertPasswordHash(
        DEVICE_AUTH_CONTROLLER_OTHER,
        (string) password_hash('correct horse battery staple', PASSWORD_DEFAULT),
        time(),
    );
    $before = $this->devices->rows[1]->publicKey;

    $response = deviceAuthControllerController()->rotateKey(deviceAuthControllerRequest([
        'public_key' => deviceAuthControllerPublicKey(),
        'email'      => DEVICE_AUTH_CONTROLLER_OTHER,
        'password'   => 'correct horse battery staple',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_wrong_member');
    expect($response->get_error_data()['status'])->toBe(403);
    expect($this->devices->rows[1]->publicKey)->toBe($before);
});

test('a credential without a token rotates nothing', function () {
    deviceAuthControllerEnrol();
    deviceAuthControllerGivenPassword('correct horse battery staple');

    $response = deviceAuthControllerController()->rotateKey(deviceAuthControllerRequest([
        'public_key' => deviceAuthControllerPublicKey(),
        'email'      => DEVICE_AUTH_CONTROLLER_MEMBER,
        'password'   => 'correct horse battery staple',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
});

test('a key fault is recorded', function () {
    // The server cannot infer this: a handset with a lost private key
    // looks perfectly healthy until a message it cannot read.
    $token = deviceAuthControllerEnrol();

    $response = deviceAuthControllerController()->reportKeyFault(deviceAuthControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->devices->rows[1]->hasKeyFault())->toBeTrue();
});

test('the session route describes the calling handset', function () {
    $token = deviceAuthControllerEnrol();

    $response = deviceAuthControllerController()->session(deviceAuthControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(((array) $response->get_data())['member']['id'])->toBe(7);
});

test('signing out revokes the device', function () {
    $token = deviceAuthControllerEnrol();

    $response = deviceAuthControllerController()->signOut(deviceAuthControllerRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->devices->rows[1]->isRevoked())->toBeTrue();
});

test('a revoked handset is refused everywhere', function () {
    // Refused because it can no longer be found, not because anything
    // downstream checks a flag. That is the whole mechanism.
    $token = deviceAuthControllerEnrol();
    $this->devices->revoke(1, time());

    foreach (['session', 'reportKeyFault'] as $route) {
        $response = deviceAuthControllerController()->{$route}(deviceAuthControllerRequest([], $token));
        expect($response)->toBeInstanceOf(WP_Error::class, $route . ' accepted a revoked device.');
    }
});

test('an unauthenticated request is refused', function () {
    $response = deviceAuthControllerController()->session(deviceAuthControllerRequest([]));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

test('an invented token is refused', function () {
    $response = deviceAuthControllerController()->session(deviceAuthControllerRequest([], 'fdt_' . str_repeat('a', 40)));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * The device cap, read from the controller rather than restated.
 *
 * A test carrying its own copy of 5 goes on passing when the cap
 * moves, and stops testing the cap.
 */
function deviceAuthControllerCap(): int
{
    $constant = new \ReflectionClassConstant(DeviceAuthController::class, 'MAX_DEVICES_PER_MEMBER');

    return (int) $constant->getValue();
}

function deviceAuthControllerController(?OAuthProvider $provider = null): DeviceAuthController
{
    $provider ??= test()->google;

    $registry = new ProviderRegistry();
    $registry->register($provider);

    $gate = new MemberGate(test()->members);

    return new DeviceAuthController(
        test()->devices,
        test()->minter,
        test()->codes,
        new DeviceRedirectValidator(),
        $gate,
        new CurrentDevice(test()->devices, test()->minter, $gate, test()->members),
        $registry,
        test()->states,
        new RateLimiter(),
        test()->audit,
        new PasswordAuthenticator(
            test()->credentials,
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
    );
}

/**
 * Enrol a handset and answer its bearer token.
 */
function deviceAuthControllerEnrol(): string
{
    $response = deviceAuthControllerController()->exchange(exchangeRequest());
    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    return (string) ((array) $response->get_data())['token'];
}

/**
 * An exchange request carrying a code the stub provider will verify.
 *
 * @param array<string, string> $overrides
 */
function exchangeRequest(array $overrides = []): WP_REST_Request
{
    $issued = test()->codes->issue(new VerifiedIdentity(DEVICE_AUTH_CONTROLLER_MEMBER, 'google', 'sub-1'));

    return deviceAuthControllerRequest(array_merge([
        'code' => $issued,
        'public_key' => deviceAuthControllerPublicKey(),
        'platform' => 'android',
        'label' => 'Pixel 6a',
    ], $overrides));
}

/**
 * @param array<string, string> $params
 */
function deviceAuthControllerRequest(array $params, string $token = ''): WP_REST_Request
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

function deviceAuthControllerGivenPassword(string $password): void
{
    test()->credentials->upsertPasswordHash(
        DEVICE_AUTH_CONTROLLER_MEMBER,
        (string) password_hash($password, PASSWORD_DEFAULT),
        time(),
    );
}

/**
 * A real RSA-2048 public key, base64 SPKI — what a handset sends.
 */
function deviceAuthControllerPublicKey(): string
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
