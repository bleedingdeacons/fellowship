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
 * Getting an access token out of a service account, and sealing a push.
 *
 * <b>The token is cached, and the cache is keyed on the account's
 * fingerprint rather than a fixed name.</b> That is what makes replacing
 * the service account take effect: a fixed key would leave a token for
 * the old project in play until it expired, pushing to a Firebase project
 * the site no longer belongs to — and failing in a way that looks like
 * the handsets' fault.
 *
 * <b>A push carries the same sealed envelope the poll does.</b> Fellowship
 * sends data-only messages precisely so the payload can be encrypted; a
 * notification block would be rendered by the system tray, which means
 * the subject and body travelling through Google in the clear and landing
 * on a lock screen. The test asserts the plaintext is nowhere in what
 * goes out.
 */

covers(\Fellowship\Push\FcmClient::class, \Fellowship\Push\FcmTransport::class);

beforeEach(function () {
    $this->privateKey = '';

    FakeWpHttp::reset();

    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($key === false) {
        $this->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
    }

    $this->key = $key;
    openssl_pkey_export($key, $this->privateKey);
});

test('a token is fetched and the message sent', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{"name":"projects/x/messages/1"}');

    expect((new FcmClient())->send(fcmTokenAccount(), ['token' => 'fcm-1']))->toBeTrue();
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('the assertion is a signed JWT for the service account', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    (new FcmClient())->send(fcmTokenAccount(), ['token' => 'fcm-1']);

    $assertion = (string) (FakeWpHttp::sentArgs(0)['body']['assertion'] ?? '');
    $parts = explode('.', $assertion);

    expect($parts)->toHaveCount(3, 'The assertion must be a three-part JWT.');

    $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);

    expect($claims)->toBeArray();
    expect($claims['iss'])->toBe('pusher@intergroup-fellowship.iam.gserviceaccount.com');
    expect($claims['aud'])->toBe('https://oauth2.googleapis.com/token');
});

test('the token is cached so a second send does not refetch it', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, '{}');

    $client = new FcmClient();
    $client->send(fcmTokenAccount(), ['token' => 'fcm-1']);
    $client->send(fcmTokenAccount(), ['token' => 'fcm-2']);

    // Three calls, not four: one token, two sends.
    expect(FakeWpHttp::callCount())->toBe(3);
});

test('replacing the service account invalidates the cached token', function () {
    // A fixed cache key would leave a token for the old project in
    // play, pushing to a Firebase project the site no longer belongs
    // to and failing as though the handsets were at fault.
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.first","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.second","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    $client = new FcmClient();
    $client->send(fcmTokenAccount(), ['token' => 'fcm-1']);
    $client->send(fcmTokenAccount('other-project'), ['token' => 'fcm-1']);

    expect(FakeWpHttp::callCount())->toBe(4);
});

test('a private key that will not load means no token and no request', function () {
    // Nothing is sent at all: without an assertion there is nothing to
    // exchange, and firing the request anyway would be a round trip
    // guaranteed to fail.
    // Built through fromJson because the constructor is private: an
    // account may only come from JSON that parsed, which is the whole
    // point of the factory.
    $broken = ServiceAccount::fromJson((string) wp_json_encode([
        'type' => 'service_account',
        'project_id' => 'intergroup-fellowship',
        'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
        'private_key' => "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
        'token_uri' => 'https://oauth2.googleapis.com/token',
    ]));

    expect($broken)->not->toBeNull();

    expect((new FcmClient())->send($broken, ['token' => 'fcm-1']))->toBeFalse();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('the send goes to the projects own endpoint', function () {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    (new FcmClient())->send(fcmTokenAccount(), ['token' => 'fcm-1']);

    expect(FakeWpHttp::sentUrl(1))->toContain('intergroup-fellowship');
    expect(FakeWpHttp::sentUrl(1))->toContain('messages:send');
});

test('a push carries no readable subject or body', function () {
    // Data-only, and sealed. A notification block would be rendered by
    // the system tray, which means the words travelling through Google
    // in the clear and landing on a lock screen.
    $settings = new Settings();
    $settings->setFcmServiceAccount(fcmTokenAccountJson());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    $transport = new FcmTransport(new FcmClient(), $settings, new MessageSealer());

    $transport->send(fcmTokenDevice(), fcmTokenMessage());

    $sent = (string) json_encode(FakeWpHttp::sentArgs(1));

    expect($sent)->not->toContain('Intergroup moved');
    expect($sent)->not->toContain('Now the 14th');
    expect($sent)->not->toContain('notification');
});

// ── Fixtures ──────────────────────────────────────────────────────

function fcmTokenAccount(string $projectId = 'intergroup-fellowship'): ServiceAccount
{
    $account = ServiceAccount::fromJson(fcmTokenAccountJson($projectId));

    expect($account)->not->toBeNull();

    return $account;
}

function fcmTokenAccountJson(string $projectId = 'intergroup-fellowship'): string
{
    // A real key, generated per run rather than committed: a fixture
    // carrying a usable service-account key would be a credential in
    // a public repository.
    return (string) wp_json_encode([
        'type' => 'service_account',
        'project_id' => $projectId,
        'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
        'private_key' => test()->privateKey,
        'token_uri' => 'https://oauth2.googleapis.com/token',
    ]);
}

function fcmTokenDevice(): Device
{
    $details = openssl_pkey_get_details(test()->key);
    expect($details)->toBeArray();

    $spki = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';

    return new Device(
        4,
        'member@example.org',
        7,
        'Pixel 6a',
        'android',
        $spki,
        'fcm',
        'fcm-1',
        1788000000,
    );
}

function fcmTokenMessage(): Message
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
