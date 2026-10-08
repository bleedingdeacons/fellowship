<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\LinkAudience;
use Fellowship\Auth\StateStore;

/**
 * Fellowship's state store: Guardian's single-use state, plus the redirect,
 * audience and context Fellowship needs back after the provider returns.
 *
 * <b>The verifier must never leave this server.</b> Only its SHA-256
 * challenge goes out on the authorise leg; the verifier itself is held in the
 * state and produced again at the token exchange. That a provider puts the
 * challenge and not the verifier on its URL is now Guardian's to test, along
 * with the providers themselves. What is left here is that this store keeps
 * the verifier, gives it back once, and keeps what Fellowship adds.
 */

covers(StateStore::class);

beforeEach(function () {
    WpState::reset();
});

test('a verifier survives the round trip', function () {
    $store = new StateStore();

    $issued = $store->issue('facebook', 'link://auth', 'the-verifier');
    $consumed = $store->consume($issued['state']);

    expect($consumed)->not->toBeNull();
    expect($consumed['code_verifier'])->toBe('the-verifier');
    expect($consumed['provider'])->toBe('facebook');
    expect($consumed['device_redirect'])->toBe('link://auth');
});

test('a flow with no verifier answers null rather than empty string', function () {
    // Google and Apple pass nothing. FacebookProvider treats an empty string
    // as "no verifier" and refuses, so a store that turned null into '' would
    // make every Facebook exchange fail with no explanation.
    $store = new StateStore();

    $consumed = $store->consume($store->issue('google', 'link://auth')['state']);

    expect($consumed)->not->toBeNull();
    expect($consumed['code_verifier'])->toBeNull();
});

test('the state is single use', function () {
    $store = new StateStore();

    $issued = $store->issue('facebook', 'link://auth', 'the-verifier');

    expect($store->consume($issued['state']))->not->toBeNull();
    expect($store->consume($issued['state']))->toBeNull('A replayed callback must find nothing.');
});

test('the audience and its context come back, and default to Link', function () {
    $store = new StateStore();

    $brokered = $store->consume($store->issue('google', 'freedom://cb', null, 'freedom', 'ctx-1')['state']);
    $link = $store->consume($store->issue('google', 'link://auth')['state']);

    expect($brokered['audience'] ?? null)->toBe('freedom');
    expect($brokered['context'] ?? null)->toBe('ctx-1');
    expect($link['audience'] ?? null)->toBe(LinkAudience::NAME);
    expect($link['context'] ?? null)->toBe('');
});

test('a state written before the move to Guardian still reads back', function () {
    // A sign-in in flight across the upgrade: the record this class wrote
    // itself, with no audience because it predates audiences too.
    WpState::$transients['fellowship_oauth_state_abc'] = [
        'provider'        => 'google',
        'nonce'           => 'n-1',
        'device_redirect' => 'link://auth',
        'code_verifier'   => null,
    ];

    expect((new StateStore())->consume('abc'))->toBe([
        'provider'        => 'google',
        'nonce'           => 'n-1',
        'device_redirect' => 'link://auth',
        'code_verifier'   => null,
        'audience'        => LinkAudience::NAME,
        'context'         => '',
    ]);
});
