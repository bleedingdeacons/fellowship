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
 */

covers(\Fellowship\Rest\DeviceAuthController::class);

const ENROLMENT_EDGES_MEMBER = 'member@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

    $this->devices = new InMemoryDeviceRepository();
    $this->codes = new DeviceCodeStore();
    $this->states = new StateStore();
    $this->minter = new DeviceTokenMinter();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: ENROLMENT_EDGES_MEMBER),
    ]);
});

test('an exchange with no credential at all is refused', function () {
    $response = enrolmentEdgesController()->exchange(enrolmentEdgesRequest([
        'public_key' => 'spki',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_credential');
});

test('a code nobody issued is refused', function () {
    $response = enrolmentEdgesController()->exchange(enrolmentEdgesRequest([
        'code' => 'never-issued',
        'public_key' => 'spki',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_code');
});

test('an id token sent for a browser provider is refused as a wiring mistake', function () {
    // The app sent an ID token for a flow that does not produce one.
    // That is a mistake in the app rather than a failed sign-in, and
    // saying so plainly is what makes it findable.
    $issued = $this->states->issue('google', '');

    $response = enrolmentEdgesController()->exchange(enrolmentEdgesRequest([
        'state' => $issued['state'],
        'id_token' => 'eyJ.header.sig',
        'public_key' => 'spki',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_wrong_flow');
});

test('an id token against a spent state is refused', function () {
    $issued = $this->states->issue('apple', '');
    $this->states->consume($issued['state']);

    $response = enrolmentEdgesController(new StubProvider('apple', serverSide: false))->exchange(enrolmentEdgesRequest([
        'state' => $issued['state'],
        'id_token' => 'eyJ.header.sig',
        'public_key' => 'spki',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_state');
});

test('a token the provider will not verify is refused', function () {
    $failing = new StubProvider('apple', serverSide: false);
    $failing->identity = null;

    $issued = $this->states->issue('apple', '');

    $response = enrolmentEdgesController($failing)->exchange(enrolmentEdgesRequest([
        'state' => $issued['state'],
        'id_token' => 'eyJ.header.sig',
        'public_key' => 'spki',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_id_token');
});

test('a client side token enrols when it verifies', function () {
    // The Apple shape, all the way through.
    $issued = $this->states->issue('apple', '');

    $response = enrolmentEdgesController(new StubProvider('apple', serverSide: false))->exchange(enrolmentEdgesRequest([
        'state' => $issued['state'],
        'id_token' => 'eyJ.header.sig',
        'public_key' => enrolmentEdgesPublicKey(),
        'platform' => 'ios',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_status())->toBe(201);
});

test('too many attempts from one address are refused', function () {
    // What stops a script working through addresses to find one the
    // gate accepts. It counts the attempt rather than the success, so
    // failing is not free.
    $controller = enrolmentEdgesController();

    $limited = false;

    for ($i = 0; $i < 40; $i++) {
        $response = $controller->exchange(enrolmentEdgesRequest([
            'code' => 'never-issued',
            'public_key' => 'spki',
            'platform' => 'android',
        ]));

        if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
            $limited = true;

            break;
        }
    }

    expect($limited)->toBeTrue('The enrolment endpoint never rate-limited a repeated caller.');
});

test('an enrolled handset describes itself back to the app', function () {
    // The app renders this on its settings screen, so a member can
    // tell which handset they are looking at.
    $token = enrolmentEdgesEnrol();

    $response = enrolmentEdgesController()->session(enrolmentEdgesRequest([], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $data = (array) $response->get_data();

    expect($data['device']['label'])->toBe('Pixel 6a');
    expect($data['device']['platform'])->toBe('android');
    expect($data['device'])->not->toHaveKey('token');
});

test('a push registration for an unknown transport is normalised', function () {
    // Only fcm means push. Anything else has to become "no push"
    // rather than a stored value the dispatcher would later try to
    // deliver through.
    $token = enrolmentEdgesEnrol();

    enrolmentEdgesController()->updatePush(enrolmentEdgesRequest([
        'push_provider' => 'carrier-pigeon',
        'push_token' => 'x',
    ], $token));

    expect($this->devices->rows[1]->pushProvider)->not->toBe('carrier-pigeon');
});

// ── Fixtures ──────────────────────────────────────────────────────

function enrolmentEdgesController(?StubProvider $provider = null): DeviceAuthController
{
    $registry = new ProviderRegistry();
    $registry->register($provider ?? new StubProvider('google', serverSide: true));

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
        new SpyAuditLogger(),
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
    );
}

function enrolmentEdgesEnrol(): string
{
    $code = test()->codes->issue(new VerifiedIdentity(ENROLMENT_EDGES_MEMBER, 'google', 'sub-1'));

    $response = enrolmentEdgesController()->exchange(enrolmentEdgesRequest([
        'code' => $code,
        'public_key' => enrolmentEdgesPublicKey(),
        'platform' => 'android',
        'label' => 'Pixel 6a',
    ]));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    return (string) ((array) $response->get_data())['token'];
}

/**
 * @param array<string, mixed> $params
 */
function enrolmentEdgesRequest(array $params, string $token = ''): WP_REST_Request
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

function enrolmentEdgesPublicKey(): string
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
