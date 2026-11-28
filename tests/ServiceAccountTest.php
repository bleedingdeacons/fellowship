<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Push\ServiceAccount;

/**
 * The site's Firebase service account, as pasted into the settings screen.
 *
 * It signs what a phone carries to the Functions, calls the admin Functions
 * and reads Firestore, so a setting that looks stored and does nothing is
 * the worst outcome: it is parsed when saved, and refused if it isn't one.
 */

covers(\Fellowship\Push\ServiceAccount::class);

test('a service account is read from its JSON', function () {
    $account = ServiceAccount::fromJson(pushAccountJson());

    expect($account)->not->toBeNull();
    expect($account->projectId)->toBe('intergroup-fellowship');
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
