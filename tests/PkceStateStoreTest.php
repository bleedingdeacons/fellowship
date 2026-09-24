<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\JwtVerifier;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Auth\StateStore;
use Fellowship\Core\Settings;

/**
 * PKCE, and the one property that makes it worth having.
 *
 * <b>The verifier must never leave this server.</b> Only its SHA-256
 * challenge goes out on the authorise leg; the verifier itself is held
 * in the state transient and produced again at the token exchange. Leak
 * it — into the start response, into the authorization URL — and PKCE
 * protects nothing at all, while still appearing to work end to end.
 * Nothing about a working sign-in would reveal the mistake, which is
 * exactly why it is asserted here.
 */

const PKCE_STATE_STORE_REDIRECT = 'https://aa-bristol.org/wp-json/fellowship/v1/auth/callback';

beforeEach(function () {
    WpState::reset();
    WpState::$options[Settings::OPTION_PUBLIC] = [
        'client_id_facebook'  => 'fb-app-id',
        'client_id_microsoft' => 'ms-client-id',
        'client_id_google'    => 'google-client-id',
    ];
});

test('a verifier survives the round trip', function () {
    $store = new StateStore();

    $issued = $store->issue('facebook', 'link://auth', 'the-verifier');
    $consumed = $store->consume($issued['state']);

    expect($consumed)->not->toBeNull();
    expect($consumed['code_verifier'])->toBe('the-verifier');
    expect($consumed['provider'])->toBe('facebook');
});

test('a flow with no verifier answers null rather than empty string', function () {
    // Google and Apple pass nothing. The distinction matters because
    // FacebookProvider treats an empty string as "no verifier" and
    // refuses; a store that turned null into '' would make every
    // Facebook exchange fail with no explanation.
    $store = new StateStore();

    $issued = $store->issue('google', 'link://auth');
    $consumed = $store->consume($issued['state']);

    expect($consumed)->not->toBeNull();
    expect($consumed['code_verifier'])->toBeNull();
});

test('the state is single use', function () {
    $store = new StateStore();

    $issued = $store->issue('facebook', 'link://auth', 'the-verifier');

    expect($store->consume($issued['state']))->not->toBeNull();
    expect($store->consume($issued['state']))->toBeNull('A replayed callback must find nothing.');
});

test('the authorization URL carries the challenge and not the verifier', function () {
    $verifier = 'a-verifier-nobody-outside-this-server-should-see';
    $url = pkceStateStoreFacebook()->getAuthorizationUrl('state-1', 'nonce-1', PKCE_STATE_STORE_REDIRECT, $verifier);

    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect($query['code_challenge_method'] ?? null)->toBe('S256');
    expect($query['code_challenge'] ?? null)->toBe(rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='));

    // The verifier must never appear in a URL that goes through a browser.
    expect($url)->not->toContain($verifier);
});

test('Facebook refuses to build a URL with no verifier', function () {
    // Loud rather than silent: a URL built without a challenge would
    // produce a token exchange that fails much later, with an error
    // naming neither this call nor the omission.
    pkceStateStoreFacebook()->getAuthorizationUrl('state-1', 'nonce-1', PKCE_STATE_STORE_REDIRECT);
})->throws(\LogicException::class);

test('Facebook refuses a callback with no verifier', function () {
    // Null here rather than the exception above: by the callback a
    // browser is waiting and the state is already spent, so this has
    // to become a redirect carrying an error rather than a 500.
    expect(pkceStateStoreFacebook()->handleCallback('a-code', 'nonce-1', PKCE_STATE_STORE_REDIRECT))->toBeNull();
});

test('only Facebook asks for PKCE', function () {
    // The controller mints a verifier from this answer alone, so a
    // provider that lied would either lose PKCE or put an unused
    // secret in a transient.
    expect(pkceStateStoreFacebook()->requiresPkce())->toBeTrue();
    expect(pkceStateStoreMicrosoft()->requiresPkce())->toBeFalse();
    expect(pkceStateStoreGoogle()->requiresPkce())->toBeFalse();
});

test('Microsoft pins the consumer tenant', function () {
    // The `common` endpoint would let any tenant admin mint a token
    // asserting any address, which is an impersonation route straight
    // past the member gate. The consumers tenant is what makes the
    // email in the token trustworthy, so it is asserted rather than
    // left to a comment.
    $url = pkceStateStoreMicrosoft()->getAuthorizationUrl('state-1', 'nonce-1', PKCE_STATE_STORE_REDIRECT);

    expect($url)->toStartWith('https://login.microsoftonline.com/consumers/');
    expect($url)->not->toContain('/common/');
});

test('the providers ask for no more than they need', function () {
    // The point of every one of these flows is a verified address.
    // A wider scope is a worse consent screen and a larger token to
    // lose, for something no part of this plugin reads.
    parse_str((string) parse_url(pkceStateStoreGoogle()->getAuthorizationUrl('s', 'n', PKCE_STATE_STORE_REDIRECT), PHP_URL_QUERY), $g);
    parse_str((string) parse_url(pkceStateStoreFacebook()->getAuthorizationUrl('s', 'n', PKCE_STATE_STORE_REDIRECT, 'v'), PHP_URL_QUERY), $f);

    expect($g['scope'] ?? null)->toBe('openid email');
    expect($f['scope'] ?? null)->toBe('openid email');

    // Microsoft is the exception, and needs saying: without `profile`
    // it will not populate preferred_username, which is the fallback
    // the address is read from when `email` is absent.
    parse_str((string) parse_url(pkceStateStoreMicrosoft()->getAuthorizationUrl('s', 'n', PKCE_STATE_STORE_REDIRECT), PHP_URL_QUERY), $m);
    expect($m['scope'] ?? null)->toBe('openid email profile');
});

test('the server side providers refuse a client supplied token', function () {
    // Reaching this would mean the registry dispatched a server-side
    // provider down the client-side path: a wiring fault, and loud.
    foreach ([pkceStateStoreGoogle(), pkceStateStoreMicrosoft(), pkceStateStoreFacebook()] as $provider) {
        expect(fn() => $provider->verifyIdToken('a.b.c', 'nonce'))
            ->toThrow(\LogicException::class, message: $provider->name() . ' accepted an ID token it cannot verify.');
    }
});

function pkceStateStoreFacebook(): FacebookProvider
{
    return new FacebookProvider(new Settings(), new JwtVerifier());
}

function pkceStateStoreMicrosoft(): MicrosoftProvider
{
    return new MicrosoftProvider(new Settings(), new JwtVerifier());
}

function pkceStateStoreGoogle(): GoogleProvider
{
    return new GoogleProvider(new Settings(), new JwtVerifier());
}
