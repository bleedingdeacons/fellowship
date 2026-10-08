<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use Fellowship\Auth\AudienceRegistry;
use Fellowship\Auth\BrokeredIdentity;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\IdentityBroker;
use Fellowship\Auth\LinkAudience;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Guardian\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Auth\VerifiedIdentity;
use Guardian\VerifiedIdentity as ProviderIdentity;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\StubAudience;
use Fellowship\Tests\Support\StubProvider;
use LogicException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Signing in on behalf of another plugin.
 *
 * <b>What must not happen is the thing this file is mostly about.</b>
 * The browser leg now serves more than Link, and the easy mistakes all
 * leak between audiences: a code issued for Freedom enrolling a Link
 * handset, a Freedom sign-in redirected to `link://auth`, a non-member
 * Freedom admits being admitted to Link, a Link member refused by a rule
 * that was only ever Link's. Each is a test below.
 *
 * And the one thing that must keep happening: Link's own sign-in behaves
 * exactly as it did before audiences existed, including a state or a code
 * written by the version before this one.
 */

covers(
    IdentityBroker::class,
    AudienceRegistry::class,
    LinkAudience::class,
    DeviceCodeStore::class,
    StateStore::class,
    DeviceAuthController::class,
    CurrentDevice::class,
);

const IDENTITY_BROKER_MEMBER = 'member@example.org';
const IDENTITY_BROKER_TABLET = 'tablet@example.org';
const IDENTITY_BROKER_REDIRECT = 'org.example.app.freedom://auth';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(
        static fn(string $path = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($path, '/')
    );

    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();
    $this->states = new StateStore();
    $this->codes = new DeviceCodeStore();
    $this->google = new StubProvider('google', serverSide: true);
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: IDENTITY_BROKER_MEMBER),
    ]);
    $this->gate = new MemberGate($this->members);
    $this->audiences = new AudienceRegistry(new LinkAudience(new DeviceRedirectValidator(), $this->gate));
    $this->freedom = new StubAudience();
    $this->audiences->register($this->freedom);
});

// ── The registry ──────────────────────────────────────────────────

test('nothing can take Link\'s name', function () {
    expect(fn() => $this->audiences->register(new StubAudience('link')))
        ->toThrow(LogicException::class);
});

test('a name cannot be registered twice', function () {
    expect(fn() => $this->audiences->register(new StubAudience('freedom')))
        ->toThrow(LogicException::class);
});

test('a name outside the allowed shape is refused', function () {
    expect(fn() => $this->audiences->register(new StubAudience('Not A Name')))
        ->toThrow(LogicException::class);
});

test('the registry must be built around Link', function () {
    expect(fn() => new AudienceRegistry(new StubAudience('freedom')))
        ->toThrow(LogicException::class);
});

// ── begin() ───────────────────────────────────────────────────────

test('begin answers a provider URL that returns to Fellowship\'s own callback', function () {
    $recording = new class implements \Guardian\Providers\OAuthProvider {
        public string $lastRedirectUri = '';

        public function name(): string
        {
            return 'google';
        }

        public function isServerSide(): bool
        {
            return true;
        }

        public function requiresPkce(): bool
        {
            return false;
        }

        public function getAuthorizationUrl(string $state, string $nonce, string $redirectUri, ?string $codeVerifier = null): string
        {
            $this->lastRedirectUri = $redirectUri;

            return 'https://accounts.example.org/authorize?state=' . $state;
        }

        public function handleCallback(string $code, string $nonce, string $redirectUri, ?string $codeVerifier = null): ?ProviderIdentity
        {
            return null;
        }

        public function verifyIdToken(string $idToken, string $nonce): ?ProviderIdentity
        {
            return null;
        }
    };

    $result = identityBrokerBroker($recording)->begin('google', 'freedom', '{"app":"register"}', IDENTITY_BROKER_REDIRECT);

    expect($result)->toBeArray();
    expect($result['authorization_url'])->toContain('state=' . $result['state']);
    // The console's registered redirect is Fellowship's, whoever asked.
    expect($recording->lastRedirectUri)->toBe('https://aa-bristol.org/wp-json/fellowship/v1/auth/callback');

    $stored = $this->states->consume($result['state']);
    expect($stored['audience'])->toBe('freedom');
    expect($stored['context'])->toBe('{"app":"register"}');
    expect($stored['device_redirect'])->toBe(IDENTITY_BROKER_REDIRECT);
});

test('begin refuses what it cannot serve', function (string $provider, string $audience, string $context, string $redirect, string $code) {
    $result = identityBrokerBroker()->begin($provider, $audience, $context, $redirect);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe($code);
})->with([
    'Link starts elsewhere'   => ['google', 'link', '', 'link://auth', 'fellowship_wrong_audience'],
    'an unknown audience'     => ['google', 'nobody', '', IDENTITY_BROKER_REDIRECT, 'fellowship_unknown_audience'],
    'an oversized context'    => ['google', 'freedom', str_repeat('x', 513), IDENTITY_BROKER_REDIRECT, 'fellowship_bad_context'],
    'an unknown provider'     => ['yahoo', 'freedom', '', IDENTITY_BROKER_REDIRECT, 'fellowship_unknown_provider'],
    'a redirect it disallows' => ['google', 'freedom', '', 'link://auth', 'fellowship_bad_redirect'],
]);

test('begin refuses a provider with no browser leg', function () {
    $result = identityBrokerBroker(new StubProvider('google', serverSide: false))
        ->begin('google', 'freedom', '', IDENTITY_BROKER_REDIRECT);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($result->get_error_code())->toBe('fellowship_wrong_flow');
});

// ── The callback, for another audience ───────────────────────────

test('another audience admits somebody who is not a member', function () {
    // A shared tablet account is nobody's membership. Link's rule would
    // refuse it; Freedom's rule is the one that applies.
    $this->google->identity = new ProviderIdentity(IDENTITY_BROKER_TABLET, 'google', 'sub-t');
    $issued = $this->states->issue('google', IDENTITY_BROKER_REDIRECT, null, 'freedom', 'ctx-1');

    $location = identityBrokerCallback($issued['state']);

    expect($location)->toStartWith(IDENTITY_BROKER_REDIRECT . '?code=');
    expect($this->freedom->contextsSeen)->toBe(['ctx-1', 'ctx-1']);

    $redeemed = identityBrokerBroker()->redeem(identityBrokerCode($location), 'freedom');
    expect($redeemed)->toBeInstanceOf(BrokeredIdentity::class);
    expect($redeemed->identity->email)->toBe(IDENTITY_BROKER_TABLET);
    expect($redeemed->context)->toBe('ctx-1');
});

test('another audience\'s refusal reaches the browser in its own words', function () {
    $this->google->identity = new ProviderIdentity('stranger@example.org', 'google', 'sub-s');
    $issued = $this->states->issue('google', IDENTITY_BROKER_REDIRECT, null, 'freedom', '');

    expect(identityBrokerCallback($issued['state']))->toBe(IDENTITY_BROKER_REDIRECT . '?error=not_authorised');
});

test('another audience\'s sign-in is never redirected to Link', function () {
    $issued = $this->states->issue('google', 'link://auth', null, 'freedom', '');

    $response = identityBrokerController()->callback(identityBrokerRequest(['state' => $issued['state'], 'code' => 'c']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_redirect');
});

test('a state naming an audience nobody registered is refused', function () {
    $issued = $this->states->issue('google', IDENTITY_BROKER_REDIRECT, null, 'departed', '');

    $response = identityBrokerController()->callback(identityBrokerRequest(['state' => $issued['state'], 'code' => 'c']));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_state');
});

test('Link still refuses somebody who is not a member', function () {
    $this->google->identity = new ProviderIdentity(IDENTITY_BROKER_TABLET, 'google', 'sub-t');
    $issued = $this->states->issue('google', 'link://auth');

    expect(identityBrokerCallback($issued['state']))->toBe('link://auth?error=not_a_member');
});

// ── Codes do not cross audiences ─────────────────────────────────

test('a code issued to another audience cannot enrol a Link handset', function () {
    $code = $this->codes->issue(new VerifiedIdentity(IDENTITY_BROKER_MEMBER, 'google', 'sub-1'), 'freedom', '');

    $response = identityBrokerController()->exchange(identityBrokerRequest([
        'code' => $code,
        'public_key' => 'irrelevant — refused before the key is read',
        'platform' => 'android',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_code');
});

test('a Link code cannot be redeemed by another audience', function () {
    $code = $this->codes->issue(new VerifiedIdentity(IDENTITY_BROKER_MEMBER, 'google', 'sub-1'));

    expect(identityBrokerBroker()->redeem($code, 'freedom'))->toBeNull();
});

test('a code tried at the wrong audience is spent', function () {
    // Otherwise a captured code could be tried at every door in turn.
    $code = $this->codes->issue(new VerifiedIdentity(IDENTITY_BROKER_TABLET, 'google', 'sub-t'), 'freedom', '');

    expect($this->codes->redeem($code, 'link'))->toBeNull();
    expect($this->codes->redeem($code, 'freedom'))->toBeNull();
});

test('another audience\'s state cannot finish a Link ID-token sign-in', function () {
    $issued = $this->states->issue('apple', '', null, 'freedom', '');

    $response = identityBrokerController(new StubProvider('apple', serverSide: false))->exchange(identityBrokerRequest([
        'state' => $issued['state'],
        'id_token' => 'x.y.z',
        'public_key' => 'irrelevant',
        'platform' => 'ios',
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_bad_state');
});

// ── Records written before audiences existed ─────────────────────

test('a state written before audiences existed reads as Link\'s', function () {
    set_transient('fellowship_oauth_state_legacy', [
        'provider' => 'google',
        'nonce' => 'n',
        'device_redirect' => 'link://auth',
        'code_verifier' => null,
    ], 600);

    $stored = $this->states->consume('legacy');

    expect($stored['audience'])->toBe('link');
    expect($stored['context'])->toBe('');
});

test('a code written before audiences existed is still Link\'s', function () {
    set_transient('fellowship_device_code_' . hash('sha256', 'legacy-code'), [
        'email' => IDENTITY_BROKER_MEMBER,
        'provider' => 'google',
        'sub' => 'sub-1',
    ], 120);

    $identity = $this->codes->consume('legacy-code');

    expect($identity)->toBeInstanceOf(VerifiedIdentity::class);
    expect($identity->email)->toBe(IDENTITY_BROKER_MEMBER);
});

// ── A Link session in place of a second sign-in ──────────────────

test('a live Link token is a session', function () {
    $token = identityBrokerEnrol();

    $session = identityBrokerBroker()->sessionFor($token);

    expect($session)->not->toBeNull();
    expect($session->email)->toBe(IDENTITY_BROKER_MEMBER);
    expect($session->memberId)->toBe(7);
    expect($session->platform)->toBe('android');
    expect(identityBrokerBroker()->isLive($session->deviceId))->toBeTrue();
});

test('a revoked Link device is no session and not live', function () {
    $token = identityBrokerEnrol();
    $session = identityBrokerBroker()->sessionFor($token);
    $this->devices->revoke($session->deviceId, time());

    expect(identityBrokerBroker()->sessionFor($token))->toBeNull();
    expect(identityBrokerBroker()->isLive($session->deviceId))->toBeFalse();
});

test('a lapsed member\'s device is no session and not live', function () {
    $token = identityBrokerEnrol();
    $session = identityBrokerBroker()->sessionFor($token);

    $this->members = new InMemoryMemberRepository([]);
    $this->gate = new MemberGate($this->members);

    expect(identityBrokerBroker()->sessionFor($token))->toBeNull();
    expect(identityBrokerBroker()->isLive($session->deviceId))->toBeFalse();
});

test('anything that is not a live token is no session', function (string $token) {
    identityBrokerEnrol();

    expect(identityBrokerBroker()->sessionFor($token))->toBeNull();
})->with([
    'empty' => [''],
    'malformed' => ['not-a-token'],
    'invented' => ['fdt_' . str_repeat('ab', 32)],
]);

test('a device that does not exist is not live', function () {
    expect(identityBrokerBroker()->isLive(0))->toBeFalse();
    expect(identityBrokerBroker()->isLive(999))->toBeFalse();
});

// ── Fixtures ──────────────────────────────────────────────────────

function identityBrokerBroker(?\Guardian\Providers\OAuthProvider $provider = null): IdentityBroker
{
    $registry = new ProviderRegistry();
    $registry->register($provider ?? test()->google);

    return new IdentityBroker(
        test()->audiences,
        $registry,
        test()->states,
        test()->codes,
        new CurrentDevice(test()->devices, test()->minter, test()->gate),
        test()->devices,
        test()->gate,
    );
}

function identityBrokerController(?\Guardian\Providers\OAuthProvider $provider = null): DeviceAuthController
{
    $registry = new ProviderRegistry();
    $registry->register($provider ?? test()->google);

    return new DeviceAuthController(
        test()->devices,
        test()->minter,
        test()->codes,
        new DeviceRedirectValidator(),
        test()->gate,
        new CurrentDevice(test()->devices, test()->minter, test()->gate),
        $registry,
        test()->states,
        new RateLimiter(),
        new SpyAuditLogger(),
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            test()->gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        test()->audiences,
    );
}

/** Run the callback for a state and answer where it redirected. */
function identityBrokerCallback(string $state): string
{
    $response = identityBrokerController()->callback(identityBrokerRequest(['state' => $state, 'code' => 'from-google']));
    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    return (string) ($response->get_headers()['Location'] ?? '');
}

function identityBrokerCode(string $location): string
{
    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    return (string) ($query['code'] ?? '');
}

/** Enrol a Link handset for the member and answer its device token. */
function identityBrokerEnrol(): string
{
    $spki = identityBrokerPublicKey();

    $response = identityBrokerController()->exchange(identityBrokerRequest([
        'code' => test()->codes->issue(new VerifiedIdentity(IDENTITY_BROKER_MEMBER, 'google', 'sub-1')),
        'public_key' => $spki,
        'platform' => 'android',
        'label' => 'Pixel',
    ]));
    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    return (string) ((array) $response->get_data())['token'];
}

/** A base64 SPKI key, generated once. Skips without OPENSSL_CONF. */
function identityBrokerPublicKey(): string
{
    static $key = null;

    if ($key === null) {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($resource === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $details = openssl_pkey_get_details($resource);
        $key = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }

    return $key;
}

/** @param array<string, string> $params */
function identityBrokerRequest(array $params): WP_REST_Request
{
    $request = new WP_REST_Request();
    foreach ($params as $key => $value) {
        $request->set_param($key, $value);
    }

    return $request;
}
