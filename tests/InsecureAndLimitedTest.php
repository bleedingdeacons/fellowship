<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use function Brain\Monkey\Actions\expectAdded;
use Fellowship\Auth\AudienceRegistry;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Guardian\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\StubAudience;
use Fellowship\Tests\Support\StubProvider;
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
 */

covers(\Fellowship\Rest\DeviceAuthController::class);

const INSECURE_AND_LIMITED_MEMBER = 'member@example.org';

/** Another audience's app, such as Freedom's: Link's browser leg is gone. */
const INSECURE_AND_LIMITED_APP = 'org.example.app.freedom://auth';

beforeEach(function () {
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    $_SERVER['REMOTE_ADDR'] = '203.0.113.4';

    $this->credentials = new InMemoryPasswordCredentialRepository();
    $this->states = new StateStore();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: INSECURE_AND_LIMITED_MEMBER),
    ]);
});

// ── Plain HTTP ────────────────────────────────────────────────────

test('every route refuses a plain request', function (string $route) {
    when('is_ssl')->justReturn(false);

    $controller = insecureAndLimitedController();

    $response = $controller->{$route}(insecureAndLimitedRequest(['email' => INSECURE_AND_LIMITED_MEMBER]));

    expect($response)->toBeInstanceOf(WP_Error::class, $route . ' answered a plain request.');
    expect($response->get_error_code())->toBe('fellowship_insecure_transport', $route . ' refused for the wrong reason.');
})->with([
    'callback' => ['callback'],
    'requestPassword' => ['requestPassword'],
    'completePassword' => ['completePassword'],
]);

// ── Too many attempts ─────────────────────────────────────────────

/**
 * @param array<string, mixed> $params
 */
test('every credential route counts the attempt', function (string $route, array $params) {
    when('is_ssl')->justReturn(true);

    $controller = insecureAndLimitedController();

    $limited = false;

    for ($i = 0; $i < 60; $i++) {
        $response = $controller->{$route}(insecureAndLimitedRequest($params));

        if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
            $limited = true;

            break;
        }
    }

    expect($limited)->toBeTrue($route . ' never rate-limited a repeated caller.');
})->with([
    'requestPassword' => ['requestPassword', ['email' => INSECURE_AND_LIMITED_MEMBER]],
    'completePassword' => ['completePassword', ['token' => 'never-issued', 'password' => 'correct horse battery staple']],
]);

// ── The rest ──────────────────────────────────────────────────────

test('the controller hooks itself onto the REST API', function () {
    // Routes registered anywhere but rest_api_init are routes that
    // exist on some requests and not others.
    expectAdded('rest_api_init')->once();

    insecureAndLimitedController()->register();
});

test('a callback carrying a target that is not the app is refused', function () {
    // The redirect carries a one-time code. It is validated again on
    // the way back rather than trusted from the state row, because a
    // state row is the one thing an attacker who reached this route
    // has already influenced.
    when('is_ssl')->justReturn(true);

    $issued = insecureAndLimitedStates()->issue('google', 'https://example.invalid/steal', null, 'freedom');

    $response = insecureAndLimitedController()->callback(insecureAndLimitedRequest([
        'state' => $issued['state'],
        'code' => 'a-code',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_redirect');
});

test('a callback for a provider that is no longer configured sends the app back', function () {
    // Not a WP_Error: the app is mid-browser-leg and the only way to
    // tell it anything is through the redirect it is waiting on. It
    // happens when an admin removes a client id while somebody is
    // half way through signing in.
    when('is_ssl')->justReturn(true);

    $issued = insecureAndLimitedStates()->issue('microsoft', INSECURE_AND_LIMITED_APP, null, 'freedom');

    $response = insecureAndLimitedController()->callback(insecureAndLimitedRequest([
        'state' => $issued['state'],
        'code' => 'a-code',
    ]));

    expect($response)->not->toBeInstanceOf(WP_Error::class);
});

test('a callback the member declined sends the app back too', function () {
    when('is_ssl')->justReturn(true);

    $issued = insecureAndLimitedStates()->issue('google', INSECURE_AND_LIMITED_APP, null, 'freedom');

    $response = insecureAndLimitedController()->callback(insecureAndLimitedRequest([
        'state' => $issued['state'],
        'error' => 'access_denied',
    ]));

    expect($response)->not->toBeInstanceOf(WP_Error::class);
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * The state store the controller under test was built with.
 *
 * Made in beforeEach rather than lazily here: `??=` through Pest's test()
 * proxy reads an undefined property and warns before it assigns.
 */
function insecureAndLimitedStates(): StateStore
{
    return test()->states;
}

function insecureAndLimitedController(?StubProvider $provider = null): DeviceAuthController
{
    $gate = new MemberGate(test()->members);

    $registry = new ProviderRegistry();
    $registry->register($provider ?? new StubProvider('google', serverSide: true));

    return new DeviceAuthController(
        $registry,
        insecureAndLimitedStates(),
        new DeviceCodeStore(),
        $gate,
        new RateLimiter(),
        new SpyAuditLogger(),
        new PasswordAuthenticator(
            test()->credentials,
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        insecureAndLimitedAudiences(),
    );
}

/** A stand-in for Freedom's audience, which is what the callback serves. */
function insecureAndLimitedAudiences(): AudienceRegistry
{
    $audiences = new AudienceRegistry();
    $audiences->register(new StubAudience('freedom', INSECURE_AND_LIMITED_APP));

    return $audiences;
}

/**
 * @param array<string, mixed> $params
 */
function insecureAndLimitedRequest(array $params, string $token = ''): WP_REST_Request
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
