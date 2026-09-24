<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\Device;
use Fellowship\Messaging\Message;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Push\ServiceAccount;

/**
 * Pushing a message to a handset.
 *
 * <b>Push is the fast path, never the reliable one</b>, and almost
 * everything here is about holding that line. Every failure below has to
 * end in false rather than an exception, because the message is already
 * stored and the handset will collect it on its next poll — a throw here
 * would turn a late message into a failed send for everybody else on the
 * same fan-out.
 *
 * The one distinction the client makes is worth keeping: a 401 or 403 is
 * a *configuration* fault that stops every push to everyone until
 * somebody fixes it, and is logged as an error. Anything else is about
 * one message — a dead registration token, a rate limit, a bad hour at
 * Google — and is a warning. Collapsing the two would either bury the
 * outage or cry wolf about a stale token.
 */

covers(\Fellowship\Push\FcmClient::class, \Fellowship\Push\FcmTransport::class, \Fellowship\Push\ServiceAccount::class);

beforeEach(function () {
    FakeWpHttp::reset();
});

// ── The service account ───────────────────────────────────────────

test('a service account is read from its JSON', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());

    expect($account)->not->toBeNull();
    expect($account->projectId)->toBe('intergroup-fellowship');
    expect($account->sendEndpoint())->toContain('intergroup-fellowship');
});

test('JSON that is not a service account is refused', function () {
    // Parsed when it is saved rather than at the first message: a
    // setting that looks stored and pushes nothing is the worst of
    // both.
    expect(ServiceAccount::fromJson(''))->toBeNull();
    expect(ServiceAccount::fromJson('not json'))->toBeNull();
    expect(ServiceAccount::fromJson('{"project_id":"x"}'))->toBeNull();
});

test('the fingerprint changes with the account', function () {
    // It keys the cached access token, so replacing the service
    // account has to invalidate the cache rather than leave a token
    // for the old project in play.
    $first = ServiceAccount::fromJson(pushAccountJson());
    $second = ServiceAccount::fromJson(pushAccountJson('other-project'));

    expect($first)->not->toBeNull();
    expect($second)->not->toBeNull();
    expect($second->fingerprint())->not->toBe($first->fingerprint());
});

test('the fingerprint is not the account', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());

    expect($account)->not->toBeNull();
    expect($account->fingerprint())->not->toContain('@');
    expect($account->fingerprint())->not->toContain('intergroup-fellowship');
});

// ── The transport ─────────────────────────────────────────────────

test('a site with no service account is not configured to push', function () {
    // Checked once by the dispatcher rather than per device, so a
    // site with no account logs one line instead of one per handset.
    expect(pushTransport()->isConfigured())->toBeFalse();
});

test('a site with a service account is configured', function () {
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    expect(pushTransport($settings)->isConfigured())->toBeTrue();
});

test('nothing is sent when there is no service account', function () {
    // False, not an exception: the message is stored and the poll
    // will fetch it.
    expect(pushTransport()->send(pushDevice(), pushMessage()))->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('a handset with no push token is not sent to', function () {
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    $device = pushDevice(pushToken: '');

    expect(pushTransport($settings)->send($device, pushMessage()))->toBeFalse();
});

test('a handset with no public key is not sent to', function () {
    // There would be nothing to seal the payload to, and an unsealed
    // push is the one thing this design refuses: the body would
    // travel through Google in the clear.
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    $device = pushDevice(publicKey: '');

    expect(pushTransport($settings)->send($device, pushMessage()))->toBeFalse();
});

// ── The client ────────────────────────────────────────────────────

test('an unreachable token endpoint means no send', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
});

test('a token endpoint that answers no token means no send', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"not_an_access_token":true}');

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
});

test('a refused send is reported rather than thrown', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    // A token, then a 403 from the send endpoint: the configuration
    // fault, which stops every push to everyone.
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(403, '{"error":{"status":"PERMISSION_DENIED"}}');

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
});

test('a dead registration token is also just false', function () {
    // Ordinary and survivable: one handset reinstalled the app.
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(404, '{"error":{"status":"NOT_FOUND"}}');

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
});

test('a message FCM accepts is a send', function () {
    // The whole path: sign an assertion, exchange it for an access
    // token, post the message. Nothing below this line is reached at
    // all unless the service-account key actually loads.
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{"name":"projects/x/messages/1"}');

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeTrue();
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('the message goes to the projects own endpoint under the token', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    (new FcmClient())->send($account, ['token' => 'fcm-1']);

    $args = FakeWpHttp::sentArgs(1);

    expect(FakeWpHttp::sentUrl(1))->toContain('intergroup-fellowship');
    expect($args['headers']['Authorization'])->toBe('Bearer ya29.token');
});

test('the access token is reused rather than minted per message', function () {
    // A fan-out to a committee is one token and many sends. Minting
    // one per handset would be an RSA signature and a round trip to
    // Google for every member.
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, '{}');

    $client = new FcmClient();
    $client->send($account, ['token' => 'fcm-1']);
    $client->send($account, ['token' => 'fcm-2']);

    expect(FakeWpHttp::callCount())->toBe(3, 'The token was minted twice.');
});

test('a send that never reaches Google is just false', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());
    expect($account)->not->toBeNull();

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
});

test('a key that will not load stops before any request', function () {
    // The failure the fixture used to have by accident, asserted on
    // purpose — and asserted by call count, which is the only thing
    // that tells it apart from a refusal further down.
    $account = ServiceAccount::fromJson((string) wp_json_encode([
        'type' => 'service_account',
        'project_id' => 'intergroup-fellowship',
        'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
        'private_key' => "-----BEGIN PRIVATE KEY-----
not-a-real-key
-----END PRIVATE KEY-----
",
        'token_uri' => 'https://oauth2.googleapis.com/token',
    ]));

    expect($account)->not->toBeNull();
    expect((new FcmClient())->send($account, ['token' => 'fcm-1']))->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

// ── Transport to client ───────────────────────────────────────────

test('a configured site seals the body and pushes it', function () {
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    $device = pushDevice(publicKey: pushPublicKey());

    expect(pushTransport($settings)->send($device, pushMessage()))->toBeTrue();
});

test('the body on the wire is sealed rather than readable', function () {
    // What the design is for: the message travels through Google, so
    // the one thing that must never be in the payload is the text.
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    pushTransport($settings)->send(pushDevice(publicKey: pushPublicKey()), pushMessage());

    $body = (string) (FakeWpHttp::sentArgs(1)['body'] ?? '');

    expect($body)->not->toContain('Now the 14th');
    expect($body)->not->toContain('Intergroup moved');
});

test('the sealed envelope reaches iOS in the APNs payload', function () {
    // iOS never sees the top-level data block as such — it reads an
    // APNs payload. FCM does merge one into the other, and the app
    // would find `k` and `p` either way, but that is a behaviour of
    // FCM's rather than a guarantee of ours: a silent push whose
    // fields did not arrive would do nothing at all rather than fail,
    // which is the hardest kind of gap to notice.
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    pushTransport($settings)->send(pushDevice(publicKey: pushPublicKey()), pushMessage());

    $sent = json_decode((string) (FakeWpHttp::sentArgs(1)['body'] ?? ''), true);
    expect($sent)->toBeArray();

    $message = $sent['message'];
    $payload = $message['apns']['payload'];

    // The same envelope in both places, and the aps dictionary intact
    // beside it.
    expect($payload['k'])->toBe($message['data']['k']);
    expect($payload['p'])->toBe($message['data']['p']);
    expect($payload['id'])->toBe($message['data']['id']);
    expect($payload['aps'])->toBe(['content-available' => 1]);
});

test('the APNs push is silent because the server cannot write the notification', function () {
    // Fellowship cannot read the message, so it cannot say anything
    // about it — the handset opens the envelope and raises its own
    // notification. A silent push is the shape that permits that, and
    // APNs refuses priority 10 for one.
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    pushTransport($settings)->send(pushDevice(publicKey: pushPublicKey()), pushMessage());

    $sent = json_decode((string) (FakeWpHttp::sentArgs(1)['body'] ?? ''), true);
    expect($sent)->toBeArray();

    $apns = $sent['message']['apns'];

    expect($apns['headers']['apns-priority'])->toBe('5');
    expect($apns['headers']['apns-push-type'])->toBe('background');
    expect($apns['payload']['aps'])->not->toHaveKey('alert', message: 'the server has nothing to display');
});

test('a handset whose key will not load is skipped rather than sent to in the clear', function () {
    // A key that is present but unusable is the case worth being
    // sure about: an empty one is refused a step earlier.
    $settings = new Settings();
    $settings->setFcmServiceAccount(pushAccountJson());

    expect(pushTransport($settings)->send(pushDevice(publicKey: 'not-a-key'), pushMessage()))->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

// ── Fixtures ──────────────────────────────────────────────────────

function pushTransport(?Settings $settings = null): FcmTransport
{
    return new FcmTransport(new FcmClient(), $settings ?? new Settings(), new MessageSealer());
}

function pushDevice(string $pushToken = 'fcm-1', string $publicKey = 'spki'): Device
{
    return new Device(
        4,
        'member@example.org',
        7,
        'Pixel 6a',
        'android',
        $publicKey,
        'fcm',
        $pushToken,
        1788000000,
    );
}

function pushMessage(): Message
{
    return new Message(
        9,
        'uuid-1',
        'dave@example.org',
        7,
        'Dave B',
        'Intergroup moved',
        'Now the 14th.',
        'committee',
        'steering',
        1788000000,
    );
}

function pushPublicKey(): string
{
    $resource = openssl_pkey_get_private(pushPrivateKey());
    expect($resource)->not->toBeFalse();

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
}

function pushAccountJson(string $projectId = 'intergroup-fellowship'): string
{
    // Structurally real, and signed with a keypair generated for this
    // run. A committed fixture must never carry a usable credential,
    // but a *fake* key is worse than useless here: the assertion is
    // signed before any HTTP call is made, so an unreadable key makes
    // every send return false at the first step and the token
    // exchange, the send and every status branch below it are never
    // reached at all. Tests written against that pass for a reason
    // that has nothing to do with what they claim to assert.
    return (string) wp_json_encode([
        'type' => 'service_account',
        'project_id' => $projectId,
        'client_email' => 'pusher@' . $projectId . '.iam.gserviceaccount.com',
        'private_key' => pushPrivateKey(),
        'token_uri' => 'https://oauth2.googleapis.com/token',
    ]);
}

/** A throwaway RSA key, generated once for the whole run. */
function pushPrivateKey(): string
{
    static $pem = null;

    if ($pem === null) {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        openssl_pkey_export($resource, $exported);
        $pem = (string) $exported;
    }

    return $pem;
}
