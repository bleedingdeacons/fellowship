<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\FirebaseCustomTokenMinter;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\MemberGate;
use Fellowship\Push\ServiceAccount;
use Fellowship\Rest\FirebaseIdentityController;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * A Unity password becoming a Firebase sign-in.
 *
 * A real authenticator over the in-memory credentials, so this exercises
 * password_verify(), and a real signing key. What matters beyond the happy
 * path is that every refusal looks the same, so this route cannot be used to
 * learn who is a member, and that neither the password nor the address reaches
 * the token.
 */

covers(FirebaseIdentityController::class);

const IDENTITY_REST_MEMBER = 'member@example.org';
const IDENTITY_REST_PASSWORD = 'correct horse battery staple';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    WpState::reset();

    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $pem = '';
    openssl_pkey_export($key, $pem);

    $this->account = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => 'fellowship-510917',
        'client_email' => 'firebase-adminsdk@fellowship-510917.iam.gserviceaccount.com',
        'private_key'  => $pem,
    ]));

    $this->credentials = new InMemoryPasswordCredentialRepository();
    $this->credentials->seedPassword(IDENTITY_REST_MEMBER, IDENTITY_REST_PASSWORD);
    $this->credentials->seedPassword('former@example.org', IDENTITY_REST_PASSWORD);

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: IDENTITY_REST_MEMBER),
    ]);
});

test('the right password answers a token for that member', function () {
    $response = identityRestController()->password(identityRestRequest());

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    $claims = identityRestClaims((string) ((array) $response->get_data())['token']);

    expect($claims['uid'])->toBe('pw_7');
    expect($claims['claims'])->toBe(['memberId' => 7, 'identity' => 'password']);
});

test('neither the password nor the address reaches the token', function () {
    $response = identityRestController()->password(identityRestRequest());

    $payload = (string) json_encode(identityRestClaims((string) ((array) $response->get_data())['token']));

    expect($payload)->not->toContain(IDENTITY_REST_PASSWORD);
    expect($payload)->not->toContain(IDENTITY_REST_MEMBER);
});

test('every refusal looks the same', function (string $email, string $password) {
    $response = identityRestController()->password(identityRestRequest($email, $password));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_credentials');
    expect($response->get_error_message())->toBe('Email or password is incorrect.');
    expect($response->get_error_data()['status'])->toBe(401);
})->with([
    'a wrong password'             => [IDENTITY_REST_MEMBER, 'wrong'],
    'an unknown address'           => ['stranger@example.org', IDENTITY_REST_PASSWORD],
    'no longer a member'           => ['former@example.org', IDENTITY_REST_PASSWORD],
    'nothing at all'               => ['', ''],
]);

test('with no service account it says so, and spends no attempt', function () {
    $this->account = null;

    $response = identityRestController()->password(identityRestRequest(IDENTITY_REST_MEMBER, 'wrong'));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_firebase_not_configured');
    expect($response->get_error_data()['status'])->toBe(503);
    expect($this->credentials->find(IDENTITY_REST_MEMBER)->failedAttempts)->toBe(0);
});

test('a key that will not sign is reported as not configured', function () {
    $this->account = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => 'fellowship-510917',
        'client_email' => 'firebase-adminsdk@fellowship-510917.iam.gserviceaccount.com',
        'private_key'  => 'not a key',
    ]));

    $response = identityRestController()->password(identityRestRequest());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_firebase_not_configured');
});

test('a request over plain http is refused', function () {
    when('is_ssl')->justReturn(false);

    $response = identityRestController()->password(identityRestRequest());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_insecure_transport');
});

test('too many attempts from one address are refused, right password or not', function () {
    $controller = identityRestController();

    for ($i = 0; $i < 30; $i++) {
        $controller->password(identityRestRequest(IDENTITY_REST_MEMBER, 'wrong'));
    }

    $response = $controller->password(identityRestRequest());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_rate_limited');
});

test('the route is registered, for POST only', function () {
    $routes = [];
    when('register_rest_route')->alias(
        function (string $namespace, string $route, array $args) use (&$routes): bool {
            $routes[$namespace . $route] = $args['methods'];

            return true;
        },
    );

    identityRestController()->registerRoutes();

    expect($routes)->toBe(['fellowship/v1/auth/identity/password' => 'POST']);
});

function identityRestController(): FirebaseIdentityController
{
    $gate = new MemberGate(test()->members);
    $account = test()->account;

    return new FirebaseIdentityController(
        new PasswordAuthenticator(
            test()->credentials,
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        $gate,
        new FirebaseCustomTokenMinter(static fn(): ?ServiceAccount => $account),
        new RateLimiter(),
    );
}

function identityRestRequest(string $email = IDENTITY_REST_MEMBER, string $password = IDENTITY_REST_PASSWORD): WP_REST_Request
{
    $request = new WP_REST_Request();
    $request->set_param('email', $email);
    $request->set_param('password', $password);

    return $request;
}

/**
 * @return array<string, mixed>
 */
function identityRestClaims(string $token): array
{
    $part = explode('.', $token)[1] ?? '';

    return (array) json_decode((string) base64_decode(strtr($part, '-_', '+/'), true), true);
}
