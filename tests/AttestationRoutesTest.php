<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\ProvenSignIn;
use Fellowship\Auth\SignInTokens;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Devices\FirebaseDevices;
use Fellowship\Devices\MemberGate;
use Fellowship\Firebase\AttestationSigner;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Firebase\GoogleTokens;
use Fellowship\Messaging\AudienceResolver;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Messaging\ResolvedAudience;
use Fellowship\Push\ServiceAccount;
use Fellowship\Rest\AttestationController;
use Guardian\Firebase\FirebaseDeviceTokenVerifier;
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
 * What a phone fetches here to carry to the Functions.
 *
 * Two things matter more than the rest. Only a fresh sign-in or a live device gets
 * a statement, and it names that sign-in or device. And a request naming nobody is
 * refused, because in MessageRequest an empty audience means everyone, and a stale
 * list must not become a broadcast.
 *
 * Real RS256 tokens and a real verifier, with only Google faked at the HTTP layer.
 * What comes back is checked against the service account's public key, as the
 * Functions check it.
 */

covers(
    AttestationController::class,
    AttestationSigner::class,
    SignInTokens::class,
    ProvenSignIn::class,
    AudienceResolver::class,
    ResolvedAudience::class,
    RecipientResolver::class,
);

const ATTEST_PROJECT = 'fellowship-510917';
const ATTEST_ACCOUNT = 'firebase-adminsdk-fbsvc@fellowship-510917.iam.gserviceaccount.com';
const ATTEST_ACCOUNT_KID = 'sa-key-1';
const ATTEST_GOOGLE_KID = 'google-key-1';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    FakeWpHttp::reset();
    WpState::reset();
    $_SERVER['REMOTE_ADDR'] = '203.0.113.' . random_int(1, 250);

    $google = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $account = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($google === false || $account === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }
    $this->googleKey = $google;
    $this->accountKey = $account;

    $pem = '';
    openssl_pkey_export($account, $pem);
    $this->accountJson = [
        'project_id'     => ATTEST_PROJECT,
        'client_email'   => ATTEST_ACCOUNT,
        'private_key'    => $pem,
        'private_key_id' => ATTEST_ACCOUNT_KID,
    ];

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

// ── /attest/member ──

test('a fresh Google sign-in of a member gets a statement naming that sign-in', function () {
    $response = attestController()->member(attestSignIn());

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(attestClaims($response))->toMatchArray([
        'iss'      => ATTEST_ACCOUNT,
        'aud'      => 'fellowship-functions:' . ATTEST_PROJECT,
        'sub'      => 'firebase-uid-1',
        'kind'     => 'member',
        'memberId' => 7,
    ]);
    expect($this->audit->entries)->toHaveCount(1);
});

test('it lasts five minutes', function () {
    $claims = attestClaims(attestController()->member(attestSignIn()));

    expect($claims['exp'] - $claims['iat'])->toBe(300);
});

test('Apple counts as Google does', function () {
    $response = attestController()->member(attestSignIn([
        'firebase' => ['sign_in_provider' => 'apple.com', 'identities' => []],
        'email'    => 'Sue@Example.org',
    ]));

    expect(attestClaims($response)['memberId'])->toBe(8);
});

test('a Unity password sign-in is the member it names', function () {
    $response = attestController()->member(attestSignIn([
        'sub'            => 'pw_10',
        'firebase'       => ['sign_in_provider' => 'custom', 'identities' => []],
        'identity'       => 'password',
        'memberId'       => 10,
        'email'          => null,
        'email_verified' => null,
    ]));

    expect(attestClaims($response))->toMatchArray(['sub' => 'pw_10', 'memberId' => 10]);
});

test('the statement never carries an address or a name', function () {
    $token = attestController()->member(attestSignIn())->get_data()['attestation'];
    $payload = (string) base64_decode(strtr(explode('.', $token)[1], '-_', '+/'));

    expect($payload)->not->toContain('example.org');
    expect($payload)->not->toContain('Dave');
});

test('a sign-in is refused', function (array $claims) {
    $response = attestController()->member(attestSignIn($claims));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_id_token');
    expect($response->get_error_data()['status'])->toBe(401);
    expect($this->audit->entries)->toBe([]);
})->with([
    'more than five minutes old'   => [['auth_time' => time() - 600]],
    'with an unverified address'   => [['email_verified' => false]],
    'with no address'              => [['email' => null]],
    'that is anonymous'            => [['firebase' => ['sign_in_provider' => 'anonymous', 'identities' => []]]],
    'that is a device'             => [['firebase' => ['sign_in_provider' => 'custom', 'identities' => []], 'kind' => 'device', 'memberId' => 7]],
    'from another project'         => [['aud' => 'somebody-else', 'iss' => 'https://securetoken.google.com/somebody-else']],
    'a password with no member'    => [['firebase' => ['sign_in_provider' => 'custom', 'identities' => []], 'identity' => 'password']],
    'after it expired'             => [['exp' => time() - 3600, 'iat' => time() - 7200]],
]);

test('no token, or a mangled one, is refused', function (string $header) {
    $request = new WP_REST_Request();
    if ($header !== '') {
        $request->set_header('authorization', $header);
    }

    $response = attestController()->member($request);

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_id_token');
})->with([
    'none'       => [''],
    'not bearer' => ['Basic abc'],
    'not a jwt'  => ['Bearer abc'],
]);

test('a token signed with some other key is refused', function () {
    $request = attestSignIn();
    $genuine = $this->googleKey;
    $this->googleKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $request->set_header('authorization', 'Bearer ' . attestIdToken());
    $this->googleKey = $genuine;

    $response = attestController()->member($request);

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_id_token');
});

test('somebody who is not a member is told so, in the words the app knows', function (array $claims) {
    $response = attestController()->member(attestSignIn($claims));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_not_a_member');
    expect($response->get_error_data()['status'])->toBe(403);
})->with([
    'unknown address'       => [['email' => 'stranger@example.org']],
    'a password the gate refuses' => [[
        'firebase'       => ['sign_in_provider' => 'custom', 'identities' => []],
        'identity'       => 'password',
        'memberId'       => 9,
        'email'          => null,
        'email_verified' => null,
    ]],
]);

test('a sign-in may ask twice, since the Functions spend it, not this', function () {
    $token = attestIdToken();

    foreach ([1, 2] as $_) {
        FakeWpHttp::pushResponse(200, attestKeySet());
        $request = new WP_REST_Request();
        $request->set_header('authorization', 'Bearer ' . $token);

        expect(attestController()->member($request))->toBeInstanceOf(WP_REST_Response::class);
    }
});

// ── What every route refuses ──

test('a site with no service account says so', function (array $json) {
    $this->accountJson = $json;

    $response = attestController()->member(attestSignIn());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_firebase_not_configured');
    expect($response->get_error_data()['status'])->toBe(503);
})->with([
    'none at all'      => [[]],
    'no key id in it'  => [['project_id' => ATTEST_PROJECT, 'client_email' => ATTEST_ACCOUNT, 'private_key' => 'x']],
]);

test('a request over plain http is refused', function () {
    when('is_ssl')->justReturn(false);

    $response = attestController()->audience(attestDeviceRequest(['memberIds' => [8]]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_insecure_transport');
});

test('one address asking too often is slowed down', function () {
    $response = null;
    for ($i = 0; $i <= 30; $i++) {
        $response = attestController()->member(new WP_REST_Request());
    }

    expect($response->get_error_code())->toBe('fellowship_rate_limited');
    expect($response->get_error_data()['status'])->toBe(429);
});

// ── /attest/audience ──

test('named members resolve to ids, signed for this device as its member', function () {
    $response = attestController()->audience(attestDeviceRequest(['memberIds' => [10, 8, 7]]));

    expect(attestClaims($response))->toMatchArray([
        'sub'            => 'd_abc',
        'kind'           => 'audience',
        'senderMemberId' => 7,
        'memberIds'      => [8, 10],
        'audience'       => 'members',
    ]);
    expect($this->audit->entries)->toHaveCount(1);
});

test('the sender is the device\'s member, whatever the body says', function () {
    $response = attestController()->audience(attestDeviceRequest(['memberIds' => [8], 'senderMemberId' => 10, 'sender_member_id' => 10]));

    expect(attestClaims($response)['senderMemberId'])->toBe(7);
});

test('a device that is not live, or a person\'s sign-in, gets nothing', function (?array $document, array $claims) {
    $response = attestController()->audience(attestDeviceRequest(['memberIds' => [8]], $document, $claims));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_unauthenticated');
})->with([
    'revoked'           => [['status' => 'revoked', 'memberId' => 7, 'tokensValidAfter' => 0], []],
    'gone'              => [null, []],
    'cut off since'     => [['status' => 'live', 'memberId' => 7, 'tokensValidAfter' => time() + 60], []],
    'a Google sign-in'  => [null, ['firebase' => ['sign_in_provider' => 'google.com', 'identities' => []]]],
]);

test('names that all turn out stale are refused, never read as everyone', function () {
    $response = attestController()->audience(attestDeviceRequest(['memberIds' => [9999]]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_recipients');
});

test('naming nobody is refused, never read as everyone', function (array $params) {
    $response = attestController()->audience(attestDeviceRequest($params));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_audience');
})->with([
    'nothing named'       => [[]],
    'an empty list'       => [['memberIds' => []]],
    'everyone'            => [['everyone' => true]],
    'everyone and a name' => [['everyone' => true, 'memberIds' => [8]]],
]);

test('committees and all GSRs need the site to allow them from the app', function (array $params) {
    $response = attestController()->audience(attestDeviceRequest($params));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_committee_send_disabled');
    expect($response->get_error_data()['status'])->toBe(403);
})->with([
    'committee' => [['committees' => ['literature']]],
    'all GSRs'  => [['gsrs' => true]],
]);

test('a committee resolves once the site allows it, sender left out', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = attestController()->audience(attestDeviceRequest(['committees' => ['literature']]));

    expect(attestClaims($response))->toMatchArray(['memberIds' => [8], 'audience' => 'part']);
});

test('a committee and a name reach both, once each', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = attestController()->audience(attestDeviceRequest(['committees' => ['literature'], 'memberIds' => [8, 10]]));

    expect(attestClaims($response))->toMatchArray(['memberIds' => [8, 10], 'audience' => 'mixed']);
});

test('a committee with nobody else on it is refused', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = attestController()->audience(attestDeviceRequest(['committees' => ['nobody-is-on-this']]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_recipients');
});

test('the same cap applies as to a send', function () {
    $this->settings->setCommitteeSendFromApp(true);

    $response = attestController()->audience(attestDeviceRequest([
        'committees' => array_map(static fn(int $i): string => 'c' . $i, range(1, MessageRequest::MAX_COMMITTEES + 1)),
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_too_many_committees');
});

// ── The routes ──

test('both routes are registered, for POST only', function () {
    $routes = [];
    when('register_rest_route')->alias(
        function (string $namespace, string $route, array $args) use (&$routes): bool {
            $routes[$namespace . $route] = $args['methods'];

            return true;
        },
    );

    attestController()->registerRoutes();

    expect($routes)->toBe([
        'fellowship/v1/attest/member'   => 'POST',
        'fellowship/v1/attest/audience' => 'POST',
    ]);
});

// ── Fixtures ──

function attestController(): AttestationController
{
    $json = test()->accountJson;
    $account = static fn(): ?ServiceAccount => ServiceAccount::fromJson($json === [] ? '' : (string) json_encode($json));
    $projectId = static fn(): string => $account()->projectId ?? '';
    $verifier = new JwtVerifier('Fellowship/test');
    $gate = new MemberGate(test()->members);
    $resolver = new RecipientResolver(test()->members, test()->committees, $gate);

    return new AttestationController(
        new AttestationSigner($account),
        new SignInTokens($verifier, $projectId),
        new FirebaseDevices(
            new FirebaseDeviceTokenVerifier($verifier),
            $projectId,
            new FirestoreClient($account, new GoogleTokens()),
            test()->members,
            $gate,
        ),
        test()->members,
        $gate,
        new AudienceResolver($resolver, test()->settings),
        new RateLimiter(),
        test()->audit,
    );
}

/**
 * The claims of the statement in a response, once its signature is checked against
 * the service account's public key.
 *
 * @return array<string, mixed>
 */
function attestClaims(WP_REST_Response|WP_Error $response): array
{
    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    [$head, $body, $signature] = explode('.', (string) $response->get_data()['attestation']);
    $decode = static fn(string $part): string => (string) base64_decode(strtr($part, '-_', '+/'));

    $public = openssl_pkey_get_details(test()->accountKey)['key'];
    expect(openssl_verify($head . '.' . $body, $decode($signature), $public, OPENSSL_ALGO_SHA256))->toBe(1);
    expect(json_decode($decode($head), true))->toBe(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => ATTEST_ACCOUNT_KID]);

    return json_decode($decode($body), true);
}

/** @param array<string, mixed> $claims */
function attestSignIn(array $claims = []): WP_REST_Request
{
    FakeWpHttp::pushResponse(200, attestKeySet());

    $request = new WP_REST_Request();
    $request->set_header('authorization', 'Bearer ' . attestIdToken($claims));

    return $request;
}

/**
 * A device's token, with the key set, a Google token and its document queued.
 *
 * @param array<string, mixed> $params
 * @param array<string, mixed>|null $document
 * @param array<string, mixed> $claims
 */
function attestDeviceRequest(
    array $params,
    ?array $document = ['status' => 'live', 'memberId' => 7, 'tokensValidAfter' => 0, 'platform' => 'android'],
    array $claims = [],
): WP_REST_Request {
    FakeWpHttp::pushResponse(200, attestKeySet());
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse($document === null ? 404 : 200, attestDocument($document));

    $request = new WP_REST_Request();
    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }
    $request->set_header('authorization', 'Bearer ' . attestIdToken(array_merge([
        'sub'            => 'd_abc',
        'kind'           => 'device',
        'memberId'       => 7,
        'firebase'       => ['sign_in_provider' => 'custom', 'identities' => []],
        'email'          => null,
        'email_verified' => null,
    ], $claims)));

    return $request;
}

/** @param array<string, mixed>|null $fields */
function attestDocument(?array $fields): string
{
    if ($fields === null) {
        return '{"error":{"code":404}}';
    }

    $encoded = [];
    foreach ($fields as $name => $value) {
        $encoded[$name] = is_int($value) ? ['integerValue' => (string) $value] : ['stringValue' => $value];
    }

    return (string) json_encode(['name' => 'x', 'fields' => $encoded]);
}

/** @param array<string, mixed> $claims A null removes the claim. */
function attestIdToken(array $claims = []): string
{
    $merged = array_filter(array_merge([
        'iss'            => 'https://securetoken.google.com/' . ATTEST_PROJECT,
        'aud'            => ATTEST_PROJECT,
        'sub'            => 'firebase-uid-1',
        'auth_time'      => time() - 5,
        'iat'            => time(),
        'exp'            => time() + 3600,
        'email'          => 'dave@example.org',
        'email_verified' => true,
        'firebase'       => ['sign_in_provider' => 'google.com', 'identities' => []],
    ], $claims), static fn(mixed $value): bool => $value !== null);

    $head = attestBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => ATTEST_GOOGLE_KID, 'typ' => 'JWT']));
    $body = attestBase64Url((string) json_encode($merged));
    $signature = '';
    openssl_sign($head . '.' . $body, $signature, test()->googleKey, OPENSSL_ALGO_SHA256);

    return $head . '.' . $body . '.' . attestBase64Url($signature);
}

function attestKeySet(): string
{
    $details = openssl_pkey_get_details(test()->googleKey);

    return (string) json_encode(['keys' => [[
        'kty' => 'RSA',
        'alg' => 'RS256',
        'kid' => ATTEST_GOOGLE_KID,
        'n'   => attestBase64Url($details['rsa']['n']),
        'e'   => attestBase64Url($details['rsa']['e']),
    ]]]);
}

function attestBase64Url(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}
