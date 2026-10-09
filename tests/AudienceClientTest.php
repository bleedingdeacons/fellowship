<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use Fellowship\Auth\AudienceProviders;
use Fellowship\Auth\AudienceRegistry;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\FixedCredentials;
use Fellowship\Auth\IdentityBroker;
use Fellowship\Auth\LinkAudience;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\ProviderClient;
use Fellowship\Auth\StateStore;
use Fellowship\Core\RateLimiter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\StubAudience;
use Fellowship\Tests\Support\StubClientAudience;
use Fellowship\Tests\Support\StubProvider;
use Guardian\Credentials\CredentialStore;
use Guardian\ProviderRegistry;
use Guardian\Providers\OAuthProvider;
use Guardian\VerifiedIdentity as ProviderIdentity;
use InvalidArgumentException;
use LogicException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_REST_Request;
use WP_REST_Response;

/**
 * An audience signing its people in with its own OAuth client.
 *
 * Register's tablets sign in through Freedom, and Freedom through this
 * broker; with one Google client for everything, a tablet was shown Link's
 * consent screen. These are the rules that let an audience bring its own:
 * the start and the callback must use the same client, everything doubtful
 * falls back to Fellowship's, and Link — which brings none — is untouched.
 */

covers(
    AudienceProviders::class,
    FixedCredentials::class,
    ProviderClient::class,
    IdentityBroker::class,
    DeviceAuthController::class,
);

const AUDIENCE_CLIENT_REDIRECT = 'org.example.app.freedom://auth';

beforeEach(function () {
    when('is_ssl')->justReturn(true);
    when('rest_url')->alias(
        static fn(string $path = ''): string => 'https://aa-bristol.org/wp-json/' . ltrim($path, '/')
    );

    // Fellowship's own client, and the one an audience's client is built as.
    $this->fellowshipGoogle = new StubProvider('google', serverSide: true);
    $this->ownGoogle = new StubProvider('google', serverSide: true);
    $this->ownGoogle->identity = new ProviderIdentity('tablet@example.org', 'google', 'sub-own');

    $this->registry = new ProviderRegistry();
    $this->registry->register($this->fellowshipGoogle);

    /** @var list<array{string, CredentialStore}> */
    $this->built = [];
    $this->build = function (string $name, CredentialStore $credentials): ?OAuthProvider {
        $this->built[] = [$name, $credentials];

        return $name === 'google' ? $this->ownGoogle : null;
    };
    $this->clients = new AudienceProviders($this->registry, $this->build);

    $this->devices = new InMemoryDeviceRepository();
    $this->minter = new DeviceTokenMinter();
    $this->states = new StateStore();
    $this->codes = new DeviceCodeStore();
    $this->gate = new MemberGate(new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'member@example.org'),
    ]));
    $this->audiences = new AudienceRegistry(new LinkAudience(new DeviceRedirectValidator(), $this->gate));
    $this->freedom = new StubClientAudience();
    $this->audiences->register($this->freedom);
});

// ── Choosing the provider ────────────────────────────────────────

test('an audience with its own client gets a provider built around it', function () {
    $provider = $this->clients->for('google', $this->freedom, 'ctx-1');

    expect($provider)->toBe($this->ownGoogle);
    expect($this->freedom->clientRequests)->toBe([['google', 'ctx-1']]);

    [$name, $credentials] = $this->built[0];
    expect($name)->toBe('google');
    expect($credentials->getClientId('google'))->toBe('register-client.apps.googleusercontent.com');
    expect($credentials->getClientSecret('google'))->toBe('register-secret');
});

test('an audience that brings no client gets Fellowship\'s', function () {
    $this->freedom->client = null;

    expect($this->clients->for('google', $this->freedom, 'ctx-1'))->toBe($this->fellowshipGoogle);
    expect($this->built)->toBe([]);
});

test('an audience that cannot bring one is never asked', function () {
    expect($this->clients->for('google', new StubAudience(), 'ctx-1'))->toBe($this->fellowshipGoogle);
    expect($this->built)->toBe([]);
});

test('a provider Fellowship did not register stays unreachable whatever the audience offers', function () {
    // Registration is the permission model; an audience's client cannot
    // open a provider the site never offered.
    expect($this->clients->for('microsoft', $this->freedom, 'ctx-1'))->toBeNull();
    expect($this->freedom->clientRequests)->toBe([]);
});

test('a provider that cannot be rebuilt falls back to Fellowship\'s', function () {
    $this->clients = new AudienceProviders($this->registry, fn(string $name, CredentialStore $c): ?OAuthProvider => null);

    expect($this->clients->for('google', $this->freedom, 'ctx-1'))->toBe($this->fellowshipGoogle);
});

test('a factory that answers a different provider is not trusted', function () {
    $this->clients = new AudienceProviders(
        $this->registry,
        fn(string $name, CredentialStore $c): ?OAuthProvider => new StubProvider('facebook', serverSide: true),
    );

    expect($this->clients->for('google', $this->freedom, 'ctx-1'))->toBe($this->fellowshipGoogle);
});

test('without overrides an audience\'s client is ignored', function () {
    expect(AudienceProviders::withoutOverrides($this->registry)->for('google', $this->freedom, 'ctx-1'))
        ->toBe($this->fellowshipGoogle);
});

// ── The client itself ────────────────────────────────────────────

test('a client needs an id', function () {
    expect(fn() => new ProviderClient('  ', 'secret'))->toThrow(InvalidArgumentException::class);
});

test('fixed credentials answer for their own provider only', function () {
    $credentials = new FixedCredentials('google', new ProviderClient('id-1', 'secret-1'));

    expect($credentials->getClientId('google'))->toBe('id-1');
    expect($credentials->getClientSecret('google'))->toBe('secret-1');
    expect($credentials->getClientId('microsoft'))->toBe('');
    expect($credentials->getClientSecret('microsoft'))->toBe('');
});

test('fixed credentials cannot be written through', function () {
    $credentials = new FixedCredentials('google', new ProviderClient('id-1', 'secret-1'));

    expect(fn() => $credentials->setClientId('google', 'other'))->toThrow(LogicException::class);
    expect(fn() => $credentials->setClientSecret('google', 'other'))->toThrow(LogicException::class);
});

// ── Through the broker and the callback ──────────────────────────

test('begin sends the browser to the audience\'s own client', function () {
    $this->ownGoogle = new class implements OAuthProvider {
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
            return 'https://accounts.example.org/own-client?state=' . $state;
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

    $result = audienceClientBroker()->begin('google', 'freedom', 'ctx-1', AUDIENCE_CLIENT_REDIRECT);

    expect($result)->toBeArray();
    expect($result['authorization_url'])->toStartWith('https://accounts.example.org/own-client?state=');
});

test('the callback exchanges the code with the client the sign-in started with', function () {
    $started = audienceClientBroker()->begin('google', 'freedom', 'ctx-1', AUDIENCE_CLIENT_REDIRECT);
    expect($started)->toBeArray();

    $location = audienceClientCallback($started['state']);

    // The own client answered (its identity is the tablet's); Fellowship's
    // stub would have answered the member, whom this audience refuses.
    expect($location)->toStartWith(AUDIENCE_CLIENT_REDIRECT . '?code=');
    expect($this->freedom->clientRequests)->toBe([['google', 'ctx-1'], ['google', 'ctx-1']]);
});

test('Link\'s callback keeps Fellowship\'s client', function () {
    // Link brings no client, so its sign-ins are exactly what they were.
    $issued = $this->states->issue('google', 'link://auth', null);

    $location = audienceClientCallback($issued['state']);

    expect($location)->toStartWith('link://auth?code=');
    expect($this->built)->toBe([]);
    expect($this->freedom->clientRequests)->toBe([]);
});

function audienceClientBroker(): IdentityBroker
{
    return new IdentityBroker(
        test()->audiences,
        test()->registry,
        test()->states,
        test()->codes,
        new CurrentDevice(test()->devices, test()->minter, test()->gate),
        test()->devices,
        test()->gate,
        new AudienceProviders(test()->registry, test()->build),
    );
}

/** Run the callback for a state and answer where it redirected. */
function audienceClientCallback(string $state): string
{
    $controller = new DeviceAuthController(
        test()->devices,
        test()->minter,
        test()->codes,
        new DeviceRedirectValidator(),
        test()->gate,
        new CurrentDevice(test()->devices, test()->minter, test()->gate),
        test()->registry,
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
        new AudienceProviders(test()->registry, test()->build),
    );

    $request = new WP_REST_Request();
    $request->set_param('state', $state);
    $request->set_param('code', 'from-google');

    $response = $controller->callback($request);
    expect($response)->toBeInstanceOf(WP_REST_Response::class);

    return (string) ($response->get_headers()['Location'] ?? '');
}
