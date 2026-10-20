<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\FirebaseSignIn;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\StateStore;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Guardian\Firebase\FirebaseIdTokenVerifier;
use Guardian\Jwt\JwtVerifier;
use Guardian\ProviderRegistry;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Native Google sign-in: a Firebase ID token as `firebase_token`.
 *
 * Guardian owns what makes a Firebase token good, and tests it. What is
 * Fellowship's is the wiring — that the token is pinned to the project
 * Fellowship pushes through, that it lands in the same enrolment as every
 * other credential (gate, key, cap and audit included), that it can prove a
 * member before a key is replaced, and that "not set up here" stays
 * distinguishable from "bad token", because Link falls back to the browser
 * on one and not the other.
 *
 * A real verifier and real RS256 tokens, with only the key-set fetch faked.
 */

covers(DeviceAuthController::class, FirebaseSignIn::class);

const FIREBASE_REST_PROJECT = 'fellowship-510917';
const FIREBASE_REST_KID = 'firebase-key-1';
const FIREBASE_REST_MEMBER = 'member@example.org';
const FIREBASE_REST_OTHER = 'other@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(
        static fn(string $path = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($path, '/')
    );
    FakeWpHttp::reset();
    WpState::reset();

    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }
    $this->signingKey = $key;
    $this->project = FIREBASE_REST_PROJECT;

    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();
    $this->audit = new SpyAuditLogger();
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: FIREBASE_REST_MEMBER),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: FIREBASE_REST_OTHER),
    ]);
});

test('a member is enrolled from a native Google sign-in', function () {
    $response = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken()));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect((string) ((array) $response->get_data())['token'])->not->toBe('');
    expect($this->devices->rows)->toHaveCount(1);
    expect(FakeWpHttp::sentUrl(0))->toBe(FirebaseIdTokenVerifier::JWKS_URL);
});

test('a native enrolment still needs a public key', function () {
    $response = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken(), ['public_key' => 'nonsense']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($this->devices->rows)->toBe([]);
});

test('a verified Google account that is not a member is refused', function () {
    $response = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken(['email' => 'stranger@example.org'])));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_not_a_member');
    expect($this->devices->rows)->toBe([]);
});

test('a token from another Firebase project is refused as a bad token', function () {
    $response = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken([
        'iss' => 'https://securetoken.google.com/someone-else',
        'aud' => 'someone-else',
    ])));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_id_token');
    expect($response->get_error_data()['status'])->toBe(401);
});

test('the same token cannot enrol two handsets', function () {
    $token = firebaseRestToken();

    firebaseRestController()->exchange(firebaseRestEnrolment($token));
    $second = firebaseRestController()->exchange(firebaseRestEnrolment($token));

    expect($second)->toBeInstanceOf(WP_Error::class);
    expect($this->devices->rows)->toHaveCount(1);
});

test('with no push service account it reports itself unavailable', function () {
    // 503 rather than 401: Link reads it as "use the browser instead".
    $this->project = '';

    $response = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken()));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_firebase_unavailable');
    expect($response->get_error_data()['status'])->toBe(503);
});

test('a controller built without native sign-in reports itself unavailable', function () {
    $response = firebaseRestController(withFirebase: false)->exchange(firebaseRestEnrolment(firebaseRestToken()));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_data()['status'])->toBe(503);
});

test('a native sign-in proves the member before a key is replaced', function () {
    $enrolled = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken()));
    $bearer = (string) ((array) $enrolled->get_data())['token'];

    $response = firebaseRestController()->rotateKey(firebaseRestRequest([
        'public_key'     => firebaseRestPublicKey(),
        'firebase_token' => firebaseRestToken(),
    ], $bearer));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
});

test('a native sign-in as somebody else cannot replace this handset key', function () {
    $enrolled = firebaseRestController()->exchange(firebaseRestEnrolment(firebaseRestToken()));
    $bearer = (string) ((array) $enrolled->get_data())['token'];

    $response = firebaseRestController()->rotateKey(firebaseRestRequest([
        'public_key'     => firebaseRestPublicKey(),
        'firebase_token' => firebaseRestToken(['email' => FIREBASE_REST_OTHER]),
    ], $bearer));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_wrong_member');
});

test('both routes declare the token unsanitised', function () {
    firebaseRestController()->registerRoutes();

    foreach (WpState::$restRoutes as $route) {
        if (in_array($route['route'], ['/auth/device/exchange', '/auth/device/key'], true)) {
            expect($route['args']['args'])->toHaveKey('firebase_token');
            expect($route['args']['args']['firebase_token'])->not->toHaveKey('sanitize_callback');
        }
    }
});

function firebaseRestController(bool $withFirebase = true): DeviceAuthController
{
    $gate = new MemberGate(test()->members);

    $firebase = $withFirebase
        ? new FirebaseSignIn(
            new FirebaseIdTokenVerifier(new JwtVerifier('Fellowship/test'), 'fellowship'),
            static fn(): string => test()->project,
        )
        : null;

    return new DeviceAuthController(
        test()->devices,
        test()->minter,
        new DeviceCodeStore(),
        new DeviceRedirectValidator(),
        $gate,
        new CurrentDevice(test()->devices, test()->minter, $gate, test()->members),
        new ProviderRegistry(),
        new StateStore(),
        new RateLimiter(),
        test()->audit,
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        null,
        null,
        $firebase,
    );
}

/**
 * @param array<string, string> $overrides
 */
function firebaseRestEnrolment(string $firebaseToken, array $overrides = []): WP_REST_Request
{
    return firebaseRestRequest(array_merge([
        'firebase_token' => $firebaseToken,
        'public_key'     => firebaseRestPublicKey(),
        'platform'       => 'android',
        'label'          => 'Pixel 6a',
    ], $overrides));
}

/**
 * @param array<string, string> $params
 */
function firebaseRestRequest(array $params, string $bearer = ''): WP_REST_Request
{
    // The key set, for whichever call reaches the verifier first; the
    // verifier caches it, so a spare queued response is harmless.
    FakeWpHttp::pushResponse(200, firebaseRestJwks());

    $request = new WP_REST_Request();
    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }
    if ($bearer !== '') {
        $request->set_header('authorization', 'Bearer ' . $bearer);
    }

    return $request;
}

/**
 * @param array<string, mixed> $claims
 */
function firebaseRestToken(array $claims = []): string
{
    $claims = array_merge([
        'iss'            => 'https://securetoken.google.com/' . FIREBASE_REST_PROJECT,
        'aud'            => FIREBASE_REST_PROJECT,
        'sub'            => 'firebase-uid-1',
        'email'          => FIREBASE_REST_MEMBER,
        'email_verified' => true,
        'auth_time'      => time() - 5,
        'iat'            => time(),
        'exp'            => time() + 3600,
        'firebase'       => ['sign_in_provider' => 'google.com', 'identities' => ['google.com' => ['1102']]],
        // Unique per call, so two tokens minted in the same second differ
        // and single use is tested only where a test means to test it.
        'jti'            => bin2hex(random_bytes(8)),
    ], $claims);

    $head = firebaseRestBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => FIREBASE_REST_KID, 'typ' => 'JWT']));
    $body = firebaseRestBase64Url((string) json_encode($claims));
    $signature = '';
    openssl_sign($head . '.' . $body, $signature, test()->signingKey, OPENSSL_ALGO_SHA256);

    return $head . '.' . $body . '.' . firebaseRestBase64Url($signature);
}

function firebaseRestJwks(): string
{
    $details = openssl_pkey_get_details(test()->signingKey);

    return (string) json_encode(['keys' => [[
        'kty' => 'RSA',
        'kid' => FIREBASE_REST_KID,
        'alg' => 'RS256',
        'n'   => firebaseRestBase64Url($details['rsa']['n']),
        'e'   => firebaseRestBase64Url($details['rsa']['e']),
    ]]]);
}

/**
 * A real RSA-2048 public key, base64 SPKI — what a handset sends.
 */
function firebaseRestPublicKey(): string
{
    static $key = null;

    if ($key === null) {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = $resource === false ? false : openssl_pkey_get_details($resource);
        if ($details === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $key = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }

    return $key;
}

function firebaseRestBase64Url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
