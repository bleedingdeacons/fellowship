<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\DeviceResolution;
use Fellowship\Devices\FirebaseDeviceResolution;
use Fellowship\Devices\FirebaseDevices;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Firebase\AdminFunctions;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Firebase\GoogleTokens;
use Fellowship\Firebase\LiveMembers;
use Fellowship\Push\ServiceAccount;
use Fellowship\Rest\DirectoryController;
use Fellowship\Sync\MemberWatch;
use Fellowship\Sync\RetentionSync;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Guardian\Firebase\FirebaseDeviceTokenVerifier;
use Guardian\Jwt\JwtVerifier;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Firebase devices, as WordPress sees them.
 *
 * Real RS256 tokens and a real verifier, with only Google faked at the HTTP layer.
 * What's worth pinning: a good signature isn't enough, an outage is never mistaken
 * for a refusal, and the daily check can't cut off the whole fellowship.
 */

covers(
    FirebaseDevices::class,
    FirestoreClient::class,
    GoogleTokens::class,
    LiveMembers::class,
    AdminFunctions::class,
    MemberWatch::class,
    RetentionSync::class,
    DirectoryController::class,
    DirectoryPresenter::class,
);

const FIREBASE_DEVICES_PROJECT = 'fellowship-510917';
const FIREBASE_DEVICES_KID = 'firebase-key-1';
const FIREBASE_DEVICES_UID = 'd_abc';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    FakeWpHttp::reset();
    WpState::reset();

    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }
    $this->signingKey = $key;

    $pem = '';
    openssl_pkey_export($key, $pem);
    $this->account = ServiceAccount::fromJson((string) json_encode([
        'project_id'   => FIREBASE_DEVICES_PROJECT,
        'client_email' => 'functions@fellowship-510917.iam.gserviceaccount.com',
        'private_key'  => $pem,
    ]));

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', showMemberProfile: true, personalEmail: 'Member@Example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', showMemberProfile: true, personalEmail: 'sue@example.org'),
        new MemberStub(id: 9, anonymousName: 'No Address', showMemberProfile: true, personalEmail: ''),
    ]);
    $this->gate = new MemberGate($this->members);
    $this->tokens = new GoogleTokens();
    $this->firestore = new FirestoreClient(fn() => test()->account, $this->tokens);
    $this->functions = new AdminFunctions(fn() => test()->account, $this->tokens);
    $this->devices = new FirebaseDevices(
        new FirebaseDeviceTokenVerifier(new JwtVerifier('Fellowship/1.0 (test)')),
        fn(): string => test()->account?->projectId ?? '',
        $this->firestore,
        $this->members,
        $this->gate,
    );
});

// ── A device's token ─────────────────────────────────────────────

test('a live device of an admitted member is found, with the address from Unity', function () {
    firebaseDevicesRespondLive();

    $device = test()->devices->resolve(firebaseDevicesToken())->device;

    expect($device?->id)->toBe(FIREBASE_DEVICES_UID);
    expect($device?->memberId)->toBe(7);
    expect($device?->email)->toBe('member@example.org');
    expect($device?->platform)->toBe('android');
});

test('the device document is read as the service account', function () {
    firebaseDevicesRespondLive();

    test()->devices->resolve(firebaseDevicesToken());

    expect(FakeWpHttp::sentUrl(2))->toContain('/databases/(default)/documents/devices/d_abc');
    expect(FakeWpHttp::sentArgs(2)['headers']['Authorization'])->toBe('Bearer google-access-token');
});

test('a token that is not a device\'s is refused without asking Firestore', function (array $claims) {
    FakeWpHttp::pushResponse(200, firebaseDevicesKeySet());

    $resolved = test()->devices->resolve(firebaseDevicesToken($claims));

    expect($resolved->refusal)->toBe(DeviceResolution::UNAUTHENTICATED);
    expect(FakeWpHttp::callCount())->toBe(1);
})->with([
    'an identity at enrolment' => [['kind' => 'identity']],
    'no kind'                  => [['kind' => null]],
    'no member'                => [['memberId' => null]],
    'a member id as text'      => [['memberId' => '7']],
    'member zero'              => [['memberId' => 0]],
    'a person\'s Google token' => [['firebase' => ['sign_in_provider' => 'google.com']]],
    'another project'          => [['aud' => 'someone-else', 'iss' => 'https://securetoken.google.com/someone-else']],
]);

test('anything that is not a token is refused without asking anybody', function (string $token) {
    expect(test()->devices->resolve($token)->refusal)->toBe(DeviceResolution::UNAUTHENTICATED);
    expect(FakeWpHttp::callCount())->toBe(0);
})->with(['', 'fdt_abc', 'one.two']);

test('no service account means nothing can be believed', function () {
    test()->account = null;

    expect(test()->devices->resolve(firebaseDevicesToken())->refusal)->toBe(DeviceResolution::UNAUTHENTICATED);
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('a device Firestore does not hold or has cut off is refused', function (array|null $document) {
    firebaseDevicesRespond($document);

    expect(test()->devices->resolve(firebaseDevicesToken())->refusal)->toBe(DeviceResolution::UNAUTHENTICATED);
})->with([
    'removed'  => [null],
    'revoked'  => [['status' => 'revoked', 'memberId' => 7]],
    'no state' => [['memberId' => 7]],
    'another member\'s device' => [['status' => 'live', 'memberId' => 8]],
]);

test('a token from before a takeover is refused while one from after it passes', function () {
    // Takeover sets tokensValidAfter, and the old phone's token stays signed.
    firebaseDevicesRespond(['status' => 'live', 'memberId' => 7, 'tokensValidAfter' => time() - 10]);

    expect(test()->devices->resolve(firebaseDevicesToken(['auth_time' => time() - 100]))->refusal)
        ->toBe(DeviceResolution::UNAUTHENTICATED);

    FakeWpHttp::reset();
    WpState::reset();
    firebaseDevicesRespond(['status' => 'live', 'memberId' => 7, 'tokensValidAfter' => time() - 10]);

    expect(test()->devices->resolve(firebaseDevicesToken(['auth_time' => time() - 5]))->device)->not->toBeNull();
});

test('a member the gate no longer admits gets the one refusal they can act on', function (int $memberId) {
    firebaseDevicesRespond(['status' => 'live', 'memberId' => $memberId]);

    $resolved = test()->devices->resolve(firebaseDevicesToken(['memberId' => $memberId]));

    expect($resolved->refusal)->toBe(DeviceResolution::NOT_A_MEMBER);
})->with(['no address' => [9], 'no longer in Unity' => [404]]);

test('a Firestore outage is not a refusal', function (int $status) {
    FakeWpHttp::pushResponse(200, firebaseDevicesKeySet());
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse($status, '{"error":{}}');

    expect(test()->devices->resolve(firebaseDevicesToken())->refusal)->toBe(FirebaseDeviceResolution::UNAVAILABLE);
})->with([500, 503, 403]);

test('no Google token is an outage too', function () {
    FakeWpHttp::pushResponse(200, firebaseDevicesKeySet());
    FakeWpHttp::pushResponse(400, '{"error":"invalid_grant"}');

    expect(test()->devices->resolve(firebaseDevicesToken())->refusal)->toBe(FirebaseDeviceResolution::UNAVAILABLE);
});

test('whether a device is live', function (array|null $document, int $status, bool $expected) {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse($status, firebaseDevicesDocument($document));

    expect(test()->devices->isLive('d_abc'))->toBe($expected);
})->with([
    'live and admitted'      => [['status' => 'live', 'memberId' => 7], 200, true],
    'revoked'                => [['status' => 'revoked', 'memberId' => 7], 200, false],
    'gone'                   => [null, 404, false],
    'member no longer gated' => [['status' => 'live', 'memberId' => 9], 200, false],
    'no member recorded'     => [['status' => 'live'], 200, false],
    'an outage leaves it live' => [null, 503, true],
]);

test('an empty device id is not live', function () {
    expect(test()->devices->isLive(''))->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

// ── The directory ────────────────────────────────────────────────

test('a device on Firebase gets the directory', function () {
    firebaseDevicesRespondLive();
    FakeWpHttp::pushResponse(200, '[{"readTime":"2026-11-06T00:00:00Z"}]');

    $response = firebaseDevicesController()->index(firebaseDevicesRequest(firebaseDevicesToken()));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect(array_column($response->get_data()['members'], 'name'))->toContain('Dave P');
    expect(test()->audit->entries)->not->toBeEmpty();
    expect((string) json_encode(test()->audit->entries))->toContain('device:' . FIREBASE_DEVICES_UID);
});

test('the directory answers each refusal differently', function (array|null $document, int $status, int $expected, string $code) {
    FakeWpHttp::pushResponse(200, firebaseDevicesKeySet());
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse($status, firebaseDevicesDocument($document));

    $response = firebaseDevicesController()->index(firebaseDevicesRequest(
        firebaseDevicesToken(['memberId' => $document['memberId'] ?? 7]),
    ));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe($code);
    expect($response->get_error_data()['status'])->toBe($expected);
})->with([
    'revoked: sign in again' => [['status' => 'revoked', 'memberId' => 7], 200, 401, 'fellowship_unauthenticated'],
    'not a member'           => [['status' => 'live', 'memberId' => 9], 200, 403, 'fellowship_not_a_member'],
    'an outage: try again'   => [null, 503, 503, 'fellowship_unavailable'],
]);

test('Fellowship\'s own device token still works beside it', function () {
    $minter = new DeviceTokenMinter();
    $token = $minter->mint();
    $table = new InMemoryDeviceRepository();
    $table->create($minter->hash($token), 'member@example.org', 7, 'Pixel', 'android', 'spki', 'fcm', 'push', 1788000000);

    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '[{"readTime":"2026-11-06T00:00:00Z"}]');

    $response = firebaseDevicesController($table, $minter)->index(firebaseDevicesRequest($token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    // The token is checked against the table, and Firestore is only asked who has a device.
    expect(FakeWpHttp::callCount())->toBe(2);
    expect(FakeWpHttp::sentUrl(1))->toContain(':runQuery');
});

test('the directory marks a member with a device on Firebase', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([8]));

    $members = array_column(firebaseDevicesPresenter()->forApp(false)['members'], 'hasDevice', 'id');

    expect($members[8])->toBeTrue();
    expect($members[7])->toBeFalse();
});

test('an outage leaves everyone selectable rather than nobody', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(503, '{}');

    $members = array_column(firebaseDevicesPresenter()->forApp(false)['members'], 'hasDevice', 'id');

    expect($members[7])->toBeTrue();
    expect($members[8])->toBeTrue();
});

test('who has a device is read once and then kept for a while', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([8]));

    $live = new LiveMembers(test()->firestore);

    expect($live->memberIds())->toBe([8 => true]);
    expect($live->memberIds())->toBe([8 => true]);
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('with no service account nobody is on Firebase, and nothing is asked', function () {
    test()->account = null;

    expect((new LiveMembers(test()->firestore))->memberIds())->toBe([]);
    expect(FakeWpHttp::callCount())->toBe(0);
});

// ── Google tokens ────────────────────────────────────────────────

test('an access token and an ID token are asked for differently and kept apart', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"the-access-token"}');
    FakeWpHttp::pushResponse(200, '{"id_token":"the-id-token"}');

    expect(test()->tokens->accessToken(test()->account, GoogleTokens::DATASTORE_SCOPE))->toBe('the-access-token');
    expect(test()->tokens->idToken(test()->account, 'https://example.org/fn'))->toBe('the-id-token');

    $claims = static function (int $index): array {
        $assertion = FakeWpHttp::sentArgs($index)['body']['assertion'];

        return json_decode(base64_decode(strtr(explode('.', $assertion)[1], '-_', '+/')), true);
    };

    expect($claims(0)['scope'])->toBe(GoogleTokens::DATASTORE_SCOPE);
    expect($claims(0))->not->toHaveKey('target_audience');
    expect($claims(1)['target_audience'])->toBe('https://example.org/fn');
    expect($claims(1))->not->toHaveKey('scope');

    // Both come from the cache now.
    expect(test()->tokens->accessToken(test()->account, GoogleTokens::DATASTORE_SCOPE))->toBe('the-access-token');
    expect(test()->tokens->idToken(test()->account, 'https://example.org/fn'))->toBe('the-id-token');
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('a token response with nothing usable gives no token', function () {
    FakeWpHttp::pushResponse(200, '{"id_token":"wrong-kind"}');

    expect(test()->tokens->accessToken(test()->account, GoogleTokens::DATASTORE_SCOPE))->toBe('');
});

// ── Retention ────────────────────────────────────────────────────

test('the retention setting reaches Firebase', function () {
    $settings = new Settings();
    $settings->setRetentionDays(45);
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');

    expect((new RetentionSync($settings, test()->firestore))->push())->toBeTrue();

    expect(FakeWpHttp::sentArgs(1)['method'])->toBe('PATCH');
    expect(FakeWpHttp::sentUrl(1))->toEndWith('/documents/config/messaging?updateMask.fieldPaths=retentionDays');
    expect(json_decode(FakeWpHttp::sentArgs(1)['body'], true))
        ->toBe(['fields' => ['retentionDays' => ['integerValue' => '45']]]);
});

test('a retention push that fails does not throw', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(503, '{}');

    expect((new RetentionSync(new Settings(), test()->firestore))->push())->toBeFalse();
});

test('with no service account there is nothing to push', function () {
    test()->account = null;

    expect((new RetentionSync(new Settings(), test()->firestore))->push())->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

// ── Keeping up with Unity ────────────────────────────────────────

test('a deleted member has their devices removed', function () {
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(200, '{"revoked":1}');

    firebaseDevicesWatch()->memberDeleted(123, test()->members->findById(7));

    expect(FakeWpHttp::sentUrl(1))->toBe('https://europe-west2-fellowship-510917.cloudfunctions.net/adminRevokeMember');
    expect(FakeWpHttp::sentArgs(1)['headers']['Authorization'])->toBe('Bearer google-id-token');
    expect(json_decode(FakeWpHttp::sentArgs(1)['body'], true))->toBe(['memberId' => 7, 'remove' => true]);
});

test('a deletion with no member to go on does nothing', function () {
    firebaseDevicesWatch()->memberDeleted(123);

    expect(FakeWpHttp::callCount())->toBe(0);
});

test('a deletion that cannot reach Firebase does not throw', function () {
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(503, '{}');

    firebaseDevicesWatch()->memberDeleted(123, test()->members->findById(7));

    expect(FakeWpHttp::callCount())->toBe(2);
});

test('the daily check revokes a member the gate refuses, and only them', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([7, 8, 9, 9]));
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(200, '{"revoked":2}');

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(5);
    expect(json_decode(FakeWpHttp::sentArgs(4)['body'], true))->toBe(['memberId' => 9, 'remove' => false]);
});

test('the daily check changes nothing when everyone is still admitted', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([7, 8]));

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(3);
});

test('the daily check will not cut off an implausible share of members', function () {
    // Unity answers with almost nobody for a moment, and revoking is final.
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([101, 102, 103, 104, 105, 106, 7, 8]));

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(3);
});

test('a few are always allowed, however small the fellowship', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([9, 101]));
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, '{}');

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(6);
});

test('the daily check does nothing when it cannot read devices', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(503, '{}');

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(3);
});

test('one refused revocation does not stop the rest', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, firebaseDevicesLive([9, 101]));
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(500, '{"reason":"fellowship_internal"}');
    FakeWpHttp::pushResponse(200, '{}');

    firebaseDevicesWatch()->daily();

    expect(FakeWpHttp::callCount())->toBe(6);
});

test('the admin call says when it fails', function () {
    FakeWpHttp::pushResponse(200, '{"id_token":"google-id-token"}');
    FakeWpHttp::pushResponse(403, '');

    expect(fn() => test()->functions->revokeMember(7))->toThrow(FirebaseUnavailable::class);
});

// ── Helpers ──────────────────────────────────────────────────────

function firebaseDevicesWatch(): MemberWatch
{
    return new MemberWatch(
        test()->members,
        test()->gate,
        test()->firestore,
        test()->functions,
        new RetentionSync(new Settings(), test()->firestore),
    );
}

function firebaseDevicesPresenter(): DirectoryPresenter
{
    return new DirectoryPresenter(
        test()->members,
        new InMemoryCommitteeRepository(),
        test()->gate,
        new InMemoryDeviceRepository(),
        null,
        null,
        new LiveMembers(test()->firestore),
    );
}

function firebaseDevicesController(?InMemoryDeviceRepository $table = null, ?DeviceTokenMinter $minter = null): DirectoryController
{
    test()->audit = new SpyAuditLogger();

    return new DirectoryController(
        new CurrentDevice($table ?? new InMemoryDeviceRepository(), $minter ?? new DeviceTokenMinter(), test()->gate),
        firebaseDevicesPresenter(),
        new Settings(),
        test()->audit,
        test()->devices,
    );
}

function firebaseDevicesRequest(string $token): WP_REST_Request
{
    $request = new WP_REST_Request();
    $request->set_header('authorization', 'Bearer ' . $token);

    return $request;
}

/** The three answers behind a check: the key set, a Google token and the device. */
function firebaseDevicesRespond(?array $document): void
{
    FakeWpHttp::pushResponse(200, firebaseDevicesKeySet());
    FakeWpHttp::pushResponse(200, '{"access_token":"google-access-token"}');
    FakeWpHttp::pushResponse($document === null ? 404 : 200, firebaseDevicesDocument($document));
}

function firebaseDevicesRespondLive(): void
{
    firebaseDevicesRespond(['status' => 'live', 'memberId' => 7, 'tokensValidAfter' => 0, 'platform' => 'android']);
}

function firebaseDevicesDocument(?array $fields): string
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

/** @param list<int> $memberIds */
function firebaseDevicesLive(array $memberIds): string
{
    return (string) json_encode(array_map(
        static fn(int $id): array => ['document' => ['fields' => ['memberId' => ['integerValue' => (string) $id]]]],
        $memberIds,
    ));
}

function firebaseDevicesKeySet(): string
{
    $details = openssl_pkey_get_details(test()->signingKey);

    return (string) json_encode(['keys' => [[
        'kty' => 'RSA',
        'alg' => 'RS256',
        'use' => 'sig',
        'kid' => FIREBASE_DEVICES_KID,
        'n'   => firebaseDevicesBase64Url($details['rsa']['n']),
        'e'   => firebaseDevicesBase64Url($details['rsa']['e']),
    ]]]);
}

/** @param array<string, mixed> $claims A null removes the claim. */
function firebaseDevicesToken(array $claims = []): string
{
    $merged = array_filter(array_merge([
        'iss'       => 'https://securetoken.google.com/' . FIREBASE_DEVICES_PROJECT,
        'aud'       => FIREBASE_DEVICES_PROJECT,
        'sub'       => FIREBASE_DEVICES_UID,
        'kind'      => 'device',
        'memberId'  => 7,
        'auth_time' => time() - 5,
        'iat'       => time(),
        'exp'       => time() + 3600,
        'firebase'  => ['sign_in_provider' => 'custom', 'identities' => []],
    ], $claims), static fn(mixed $value): bool => $value !== null);

    $head = firebaseDevicesBase64Url((string) json_encode(['alg' => 'RS256', 'kid' => FIREBASE_DEVICES_KID, 'typ' => 'JWT']));
    $body = firebaseDevicesBase64Url((string) json_encode($merged));
    $signature = '';
    openssl_sign($head . '.' . $body, $signature, test()->signingKey, OPENSSL_ALGO_SHA256);

    return $head . '.' . $body . '.' . firebaseDevicesBase64Url($signature);
}

function firebaseDevicesBase64Url(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}
