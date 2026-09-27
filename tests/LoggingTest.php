<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Core\Settings;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\LoggingController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Link's log-shipping settings, which the server hands to signed-in
 * handsets so the app does not have to carry them.
 *
 * <b>The token reaches enrolled handsets and nothing else.</b> That is
 * the whole of what moving it out of the app buys, so the refusals are
 * tested as carefully as the answer: no token, a revoked token, plain
 * HTTP.
 *
 * <b>Both fields or neither.</b> Half a configuration is answered as none,
 * so the app has two cases rather than four.
 */

covers(LoggingController::class, Settings::class);

const LOGGING_MEMBER = 'member@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    $_POST = [];

    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();
    $this->settings = new Settings();
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: LOGGING_MEMBER),
    ]);
});

// ── The route ─────────────────────────────────────────────────────

test('an enrolled handset is told where to ship and with what', function () {
    $this->settings->setLogEndpoint('s123456.eu-central-1a.betterstackdata.com');
    $this->settings->setLogSourceToken('src-token');

    $response = loggingController()->show(loggingRequest(loggingEnrol()));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_data())->toBe([
        'endpoint'     => 'https://s123456.eu-central-1a.betterstackdata.com',
        'source_token' => 'src-token',
    ]);
});

test('the answer is never cached', function () {
    // It carries a credential. WordPress sends no-cache headers only for
    // a logged-in user, and a device token is not one.
    $this->settings->setLogEndpoint('https://s1.betterstackdata.com');
    $this->settings->setLogSourceToken('src-token');

    $response = loggingController()->show(loggingRequest(loggingEnrol()));

    expect($response->get_headers())->toHaveKey('Cache-Control', 'no-store');
});

test('nothing configured answers empty rather than refusing', function () {
    // "Do not ship" is an answer the app acts on - it drops what it was
    // holding - so it must not look like a failure it would retry.
    $response = loggingController()->show(loggingRequest(loggingEnrol()));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($response->get_data())->toBe(['endpoint' => '', 'source_token' => '']);
});

test('an endpoint with no token is answered as nothing', function () {
    $this->settings->setLogEndpoint('https://s1.betterstackdata.com');

    expect(loggingController()->show(loggingRequest(loggingEnrol()))->get_data())
        ->toBe(['endpoint' => '', 'source_token' => '']);
});

test('a token with no endpoint is answered as nothing', function () {
    $this->settings->setLogSourceToken('src-token');

    expect(loggingController()->show(loggingRequest(loggingEnrol()))->get_data())
        ->toBe(['endpoint' => '', 'source_token' => '']);
});

test('an unauthenticated request is refused', function () {
    $this->settings->setLogEndpoint('https://s1.betterstackdata.com');
    $this->settings->setLogSourceToken('src-token');

    $response = loggingController()->show(loggingRequest());

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_data())->toBe(['status' => 401]);
});

test('a revoked handset is refused', function () {
    // Revoking from the Devices screen has to stop the token being
    // handed out again, or revoking would not cut a lost phone off from
    // the log source.
    $token = loggingEnrol();
    $this->devices->revoke(1, time());

    expect(loggingController()->show(loggingRequest($token)))->toBeInstanceOf(WP_Error::class);
});

test('a handset whose member has gone is told so', function () {
    $token = loggingEnrol();
    $this->members = new InMemoryMemberRepository([]);

    $response = loggingController()->show(loggingRequest($token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_data())->toBe(['status' => 403]);
});

test('plain HTTP is refused', function () {
    when('is_ssl')->justReturn(false);

    expect(loggingController()->show(loggingRequest(loggingEnrol())))->toBeInstanceOf(WP_Error::class);
});

// ── Where it is stored ────────────────────────────────────────────

test('the token is held with the secrets, encrypted', function () {
    $this->settings->setLogSourceToken('src-token');

    $public = (string) json_encode(WpState::$options[Settings::OPTION_PUBLIC] ?? []);
    $secrets = (string) json_encode(WpState::$options[Settings::OPTION_SECRETS] ?? []);

    expect($public)->not->toContain('src-token');
    expect($secrets)->not->toContain('src-token');
    expect($this->settings->getLogSourceToken())->toBe('src-token');
});

test('the endpoint is given https when pasted bare', function () {
    // Better Stack's dashboard shows it as a host name, so that is what
    // gets pasted.
    expect(Settings::normaliseLogEndpoint('s1.betterstackdata.com'))->toBe('https://s1.betterstackdata.com');
    expect(Settings::normaliseLogEndpoint(' https://s1.betterstackdata.com/ '))->toBe('https://s1.betterstackdata.com');
    expect(Settings::normaliseLogEndpoint(''))->toBe('');
});

test('an endpoint that is not https is refused', function () {
    // Refused rather than upgraded: plain http is a mistake to point out.
    expect(Settings::normaliseLogEndpoint('http://s1.betterstackdata.com'))->toBeNull();
    expect(Settings::normaliseLogEndpoint('ftp://s1.betterstackdata.com'))->toBeNull();
    expect(Settings::normaliseLogEndpoint('https://'))->toBeNull();
});

// ── The settings screen ───────────────────────────────────────────

test('the screen saves the endpoint and token', function () {
    $_POST['log_endpoint'] = 's1.betterstackdata.com';
    $_POST['log_source_token'] = 'src-token';

    expect((new SettingsPage($this->settings))->saveFromRequest())->toBe('saved');
    expect($this->settings->getLogEndpoint())->toBe('https://s1.betterstackdata.com');
    expect($this->settings->getLogSourceToken())->toBe('src-token');
});

test('a blank token field keeps the stored one', function () {
    // The field is never filled with the stored value, so blank is the
    // normal case for anyone saving something else on the screen.
    $this->settings->setLogSourceToken('src-token');

    (new SettingsPage($this->settings))->saveFromRequest();

    expect($this->settings->getLogSourceToken())->toBe('src-token');
});

test('the checkbox clears the token', function () {
    $this->settings->setLogSourceToken('src-token');
    $_POST['clear_log_source_token'] = '1';

    (new SettingsPage($this->settings))->saveFromRequest();

    expect($this->settings->getLogSourceToken())->toBe('');
});

test('an http endpoint is refused before anything is written', function () {
    // The notice says nothing was changed, which has to be true of the
    // whole form rather than only the field at fault.
    $_POST['log_endpoint'] = 'http://s1.betterstackdata.com';
    $_POST['log_source_token'] = 'src-token';
    $_POST['google_client_id'] = 'google-client-id';

    expect((new SettingsPage($this->settings))->saveFromRequest())->toBe('bad_log_endpoint');
    expect($this->settings->getLogEndpoint())->toBe('');
    expect($this->settings->getLogSourceToken())->toBe('');
    expect($this->settings->getClientId('google'))->toBe('');
});

// ── Fixtures ──────────────────────────────────────────────────────

function loggingController(): LoggingController
{
    $gate = new MemberGate(test()->members);

    return new LoggingController(
        new CurrentDevice(test()->devices, test()->minter, $gate, test()->members),
        test()->settings,
    );
}

function loggingEnrol(): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        LOGGING_MEMBER,
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );

    return $token;
}

function loggingRequest(string $token = ''): WP_REST_Request
{
    $request = new WP_REST_Request();

    if ($token !== '') {
        $request->set_header('authorization', 'Bearer ' . $token);
    }

    return $request;
}
