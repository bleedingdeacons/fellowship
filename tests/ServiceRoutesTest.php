<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\ServiceCaller;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Rest\ServiceController;
use Guardian\Jwt\JwtVerifier;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * What Link's Cloud Functions may ask about members.
 *
 * Two things here matter more than the rest. Only this project's service
 * account gets an answer, since every Google account can get a Google-signed
 * token. And a request naming nobody is refused, because in MessageRequest an
 * empty audience means everyone, and a stale list must not become a broadcast.
 *
 * A real verifier and real RS256 tokens, with only the key-set fetch faked.
 */

covers(ServiceController::class, ServiceCaller::class, MessageRequest::class);

const SERVICE_ROUTES_ACCOUNT = 'firebase-adminsdk@fellowship-510917.iam.gserviceaccount.com';
const SERVICE_ROUTES_AUDIENCE = 'https://aa-bristol.org/wp-json/fellowship/v1/service';
const SERVICE_ROUTES_KID = 'google-key-1';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    FakeWpHttp::reset();
    WpState::reset();

    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }
    $this->signingKey = $key;

    $this->serviceAccount = SERVICE_ROUTES_ACCOUNT;
    $this->audit = new SpyAuditLogger();
    $this->settings = new Settings();
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
        new MemberStub(id: 9, anonymousName: 'No Address', personalEmail: ''),
        new MemberStub(id: 10, anonymousName: 'Pat R', personalEmail: 'pat@example.org'),
    ]);
    $this->committees = new InMemoryCommitteeRepository(
        [new CommitteeStub(id: 2, slug: 'literature', name: 'Literature')],
        ['literature' => [7, 8]],
    );
});

// ── Who may ask ──

test('a token from the service account is accepted', function () {
    $response = serviceRoutesController()->member(serviceRoutesRequest(['email' => 'dave@example.org']));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(FakeWpHttp::sentUrl(0))->toBe(ServiceCaller::JWKS_URL);
});

test('a caller is refused', function (array $claims) {
    $response = serviceRoutesController()->member(
        serviceRoutesRequest(['email' => 'dave@example.org'], serviceRoutesToken($claims)),
    );

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
    expect($response->get_error_data()['status'])->toBe(401);
    expect($this->audit->entries)->toBe([]);
})->with([
    'with any other Google account' => [['email' => 'somebody@gmail.com']],
    'with an unverified email'      => [['email_verified' => false]],
    'with no email at all'          => [['email' => null]],
    'for another audience'          => [['aud' => 'https://elsewhere.example.org/']],
    'from another issuer'           => [['iss' => 'https://securetoken.google.com/fellowship-510917']],
    'after it expired'              => [['exp' => 1000000000, 'iat' => 999999000]],
]);

test('a caller with no token, or a mangled one, is refused', function (string $header) {
    $request = new WP_REST_Request();
    $request->set_param('email', 'dave@example.org');
    if ($header !== '') {
        $request->set_header('authorization', $header);
    }
    FakeWpHttp::pushResponse(200, serviceRoutesJwks());

    $response = serviceRoutesController()->audience($request);

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
})->with([
    'none'       => [''],
    'not bearer' => ['Basic abc'],
    'not a jwt'  => ['Bearer abc'],
]);

test('a token signed with some other key is refused', function () {
    $genuine = $this->signingKey;
    $forged = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

    // The key set is the genuine key's, the token is signed with another.
    $request = serviceRoutesRequest(['email' => 'dave@example.org']);
    $this->signingKey = $forged;
    $request->set_header('authorization', 'Bearer ' . serviceRoutesToken());
    $this->signingKey = $genuine;

    $response = serviceRoutesController()->member($request);

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
});

test('a site with no service account says so', function () {
    $this->serviceAccount = '';

    $response = serviceRoutesController()->member(serviceRoutesRequest(['email' => 'dave@example.org']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_firebase_not_configured');
    expect($response->get_error_data()['status'])->toBe(503);
});

test('a request over plain http is refused', function () {
    when('is_ssl')->justReturn(false);

    $response = serviceRoutesController()->member(serviceRoutesRequest(['email' => 'dave@example.org']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_insecure_transport');
});

// ── /service/member ──

test('a member is found by email or by id', function (array $params) {
    $response = serviceRoutesController()->member(serviceRoutesRequest($params));

    expect($response->get_data())->toBe(['member_id' => 7, 'admitted' => true]);
    expect($this->audit->entries)->toHaveCount(1);
})->with([
    'email'          => [['email' => 'dave@example.org']],
    'email in caps'  => [['email' => ' Dave@Example.org ']],
    'id'             => [['member_id' => 7]],
]);

test('somebody unknown is an answer rather than an error', function () {
    $response = serviceRoutesController()->member(serviceRoutesRequest(['email' => 'stranger@example.org']));

    expect($response->get_status())->toBe(200);
    expect($response->get_data())->toBe(['member_id' => 0, 'admitted' => false]);
    expect($this->audit->entries)->toBe([]);
});

test('a member the gate refuses comes back as not admitted', function () {
    $response = serviceRoutesController()->member(serviceRoutesRequest(['member_id' => 9]));

    expect($response->get_data())->toBe(['member_id' => 9, 'admitted' => false]);
});

test('the answer never carries an address or a name', function () {
    $response = serviceRoutesController()->member(serviceRoutesRequest(['email' => 'dave@example.org']));
    $body = (string) json_encode($response->get_data());

    expect($body)->not->toContain('example.org');
    expect($body)->not->toContain('Dave');
});

test('a request must name exactly one member', function (array $params) {
    $response = serviceRoutesController()->member(serviceRoutesRequest($params));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_request');
})->with([
    'neither' => [[]],
    'both'    => [['email' => 'dave@example.org', 'member_id' => 7]],
]);

// ── /service/audience ──

test('named members resolve to ids, with the sender left out', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 7,
        'member_ids'       => [10, 8, 7],
    ]));

    expect($response->get_data())->toBe(['member_ids' => [8, 10]]);
    expect($this->audit->entries)->toHaveCount(1);
});

test('the answer never carries an address', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 7,
        'member_ids'       => [8],
    ]));

    expect((string) json_encode($response->get_data()))->not->toContain('example.org');
});

test('names that all turn out stale are refused, never read as everyone', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'           => 'admin',
        'sender_member_id' => 7,
        'member_ids'       => [9999],
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_recipients');
});

test('naming nobody is refused, never read as everyone', function (string $origin, array $params) {
    $response = serviceRoutesController()->audience(serviceRoutesRequest(
        ['origin' => $origin, 'sender_member_id' => 7] + $params,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_audience');
})->with([
    'a member, nothing named'   => ['member', []],
    'an admin, nothing named'   => ['admin', []],
    'an admin, an empty list'   => ['admin', ['member_ids' => []]],
    'a blank committee'         => ['admin', ['committees' => ['   ']]],
]);

test('a handset may not address everyone', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 7,
        'everyone'         => true,
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_audience');
});

test('the Compose screen may address everyone, when it asks for it', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'   => 'admin',
        'everyone' => true,
    ]));

    // Member 9 has no address, so the gate leaves them out.
    expect($response->get_data())->toBe(['member_ids' => [7, 8, 10]]);
});

test('everyone cannot be combined with anybody in particular', function (array $params) {
    $response = serviceRoutesController()->audience(serviceRoutesRequest(
        ['origin' => 'admin', 'everyone' => true] + $params,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_audience');
})->with([
    'named'     => [['member_ids' => [8]]],
    'committee' => [['committees' => ['literature']]],
]);

test('committees and all GSRs need the site to allow them from the app', function (array $params) {
    $response = serviceRoutesController()->audience(serviceRoutesRequest(
        ['sender_member_id' => 10] + $params,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_committee_send_disabled');
    expect($response->get_error_data()['status'])->toBe(403);
})->with([
    'committee' => [['committees' => ['literature']]],
    'all GSRs'  => [['gsrs' => true]],
]);

test('a committee resolves once the site allows it', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 7,
        'committees'       => ['literature'],
    ]));

    expect($response->get_data())->toBe(['member_ids' => [8]]);
});

test('the Compose screen needs no such permission', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'     => 'admin',
        'committees' => ['literature'],
    ]));

    expect($response->get_data())->toBe(['member_ids' => [7, 8]]);
});

test('a committee and a name reach both, once each', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 10,
        'committees'       => ['literature'],
        'member_ids'       => [8],
    ]));

    expect($response->get_data())->toBe(['member_ids' => [7, 8]]);
});

test('stale names beside a real committee do not stop the send', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'sender_member_id' => 10,
        'committees'       => ['literature'],
        'member_ids'       => [9999],
    ]));

    expect($response->get_data())->toBe(['member_ids' => [7, 8]]);
});

test('a committee with nobody on it is refused', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'     => 'admin',
        'committees' => ['nobody-is-on-this'],
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_recipients');
});

test('a sender who is not a member is refused', function (array $params) {
    $response = serviceRoutesController()->audience(serviceRoutesRequest(
        ['member_ids' => [8]] + $params,
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_not_a_member');
})->with([
    'unknown'            => [['sender_member_id' => 9999]],
    'the gate refuses'   => [['sender_member_id' => 9]],
    'no sender at all'   => [[]],
]);

test('an unknown origin is refused rather than treated as a member', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'           => 'superuser',
        'sender_member_id' => 7,
        'member_ids'       => [8],
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_request');
});

test('the same cap applies as to a send', function () {
    $response = serviceRoutesController()->audience(serviceRoutesRequest([
        'origin'     => 'admin',
        'committees' => array_map(static fn(int $i): string => 'c' . $i, range(1, MessageRequest::MAX_COMMITTEES + 1)),
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_too_many_committees');
});

// ── The request and the routes ──

test('an audience needs no subject or body', function () {
    $built = MessageRequest::forAudience(['member_emails' => ['dave@example.org']]);

    expect($built)->toBeInstanceOf(MessageRequest::class);
    expect($built->audienceType)->toBe(Message::AUDIENCE_MEMBERS);
});

test('both routes are registered, for POST only', function () {
    $routes = [];
    when('register_rest_route')->alias(
        function (string $namespace, string $route, array $args) use (&$routes): bool {
            $routes[$namespace . $route] = $args['methods'];

            return true;
        },
    );

    serviceRoutesController()->registerRoutes();

    expect($routes)->toBe([
        'fellowship/v1/service/member'   => 'POST',
        'fellowship/v1/service/audience' => 'POST',
    ]);
});

function serviceRoutesController(): ServiceController
{
    $gate = new MemberGate(test()->members);
    $account = test()->serviceAccount;

    return new ServiceController(
        new ServiceCaller(
            new JwtVerifier('Fellowship/test'),
            static fn(): string => $account,
            static fn(): string => SERVICE_ROUTES_AUDIENCE,
        ),
        test()->members,
        $gate,
        new RecipientResolver(test()->members, test()->committees, $gate),
        test()->settings,
        test()->audit,
    );
}

/**
 * @param array<string, mixed> $params
 */
function serviceRoutesRequest(array $params, ?string $token = null): WP_REST_Request
{
    // The key set, for whichever call reaches the verifier first; the
    // verifier caches it, so a spare queued response is harmless.
    FakeWpHttp::pushResponse(200, serviceRoutesJwks());

    $request = new WP_REST_Request();
    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }
    $request->set_header('authorization', 'Bearer ' . ($token ?? serviceRoutesToken()));

    return $request;
}

/**
 * @param array<string, mixed> $claims A null value removes the claim.
 */
function serviceRoutesToken(array $claims = []): string
{
    $claims = array_filter(array_merge([
        'iss'            => ServiceCaller::ISSUER,
        'aud'            => SERVICE_ROUTES_AUDIENCE,
        'sub'            => '1234567890',
        'email'          => SERVICE_ROUTES_ACCOUNT,
        'email_verified' => true,
        'iat'            => time(),
        'exp'            => time() + 3600,
    ], $claims), static fn(mixed $value): bool => $value !== null);

    $head = serviceRoutesBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => SERVICE_ROUTES_KID, 'typ' => 'JWT']));
    $body = serviceRoutesBase64Url((string) json_encode($claims));
    $signature = '';
    openssl_sign($head . '.' . $body, $signature, test()->signingKey, OPENSSL_ALGO_SHA256);

    return $head . '.' . $body . '.' . serviceRoutesBase64Url($signature);
}

function serviceRoutesJwks(): string
{
    $details = openssl_pkey_get_details(test()->signingKey);

    return (string) json_encode(['keys' => [[
        'kty' => 'RSA',
        'kid' => SERVICE_ROUTES_KID,
        'alg' => 'RS256',
        'n'   => serviceRoutesBase64Url($details['rsa']['n']),
        'e'   => serviceRoutesBase64Url($details['rsa']['e']),
    ]]]);
}

function serviceRoutesBase64Url(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
