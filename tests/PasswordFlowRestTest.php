<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
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
    $this->mailer = new PasswordResetMailer();
    $this->audit = new SpyAuditLogger();

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
        $registry,
        new StateStore(),
        new DeviceCodeStore(),
        $gate,
        new RateLimiter(),
        test()->audit,
        new PasswordAuthenticator(test()->credentials, $gate, test()->mailer, new PasswordPolicy()),
        new AudienceRegistry(),
    );
}

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
