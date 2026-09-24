<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Settings;

/**
 * What the settings screen stores, and where.
 *
 * <b>The split between the two options rows is the point.</b> Client ids,
 * the retention window and the committee-send flag live in
 * `fellowship_settings`; client secrets and the Firebase service account
 * live encrypted in `fellowship_secrets`. That makes "is this safe to
 * show?" a property of where the value lives rather than of who
 * remembered — and it is asserted here by reading the raw options back
 * and checking a secret is not in the public one.
 */

covers(\Fellowship\Core\Settings::class);

beforeEach(function () {
    $this->settings = new Settings();
});

test('a client id round trips', function () {
    $this->settings->setClientId('google', 'google-client-id');

    expect($this->settings->getClientId('google'))->toBe('google-client-id');
});

test('an unset client id is empty rather than null', function () {
    // Every caller concatenates or compares it; a null would be a
    // deprecation at best and a wrong comparison at worst.
    expect($this->settings->getClientId('google'))->toBe('');
});

test('providers do not share a client id', function () {
    $this->settings->setClientId('google', 'google-client-id');
    $this->settings->setClientId('microsoft', 'ms-client-id');

    expect($this->settings->getClientId('google'))->toBe('google-client-id');
    expect($this->settings->getClientId('microsoft'))->toBe('ms-client-id');
});

test('a client secret round trips', function () {
    $this->settings->setClientSecret('google', 'a-client-secret');

    expect($this->settings->getClientSecret('google'))->toBe('a-client-secret');
});

test('a secret is never stored in the public row', function () {
    // The row that anything reading options might reasonably print.
    $this->settings->setClientSecret('google', 'a-client-secret');

    $public = (string) json_encode(WpState::$options[Settings::OPTION_PUBLIC] ?? []);

    expect($public)->not->toContain('a-client-secret');
});

test('a secret is not stored in the clear', function () {
    $this->settings->setClientSecret('google', 'a-client-secret');

    $secrets = (string) json_encode(WpState::$options[Settings::OPTION_SECRETS] ?? []);

    expect($secrets)->not->toContain('a-client-secret');
});

test('clearing a secret leaves nothing behind', function () {
    $this->settings->setClientSecret('google', 'a-client-secret');
    $this->settings->setClientSecret('google', '');

    expect($this->settings->getClientSecret('google'))->toBe('');
});

test('the service account is held with the secrets', function () {
    // It can push to every handset on the project. It is the most
    // dangerous single value this plugin stores.
    $this->settings->setFcmServiceAccount('{"project_id":"x"}');

    $public = (string) json_encode(WpState::$options[Settings::OPTION_PUBLIC] ?? []);

    expect($this->settings->getFcmServiceAccount())->toBe('{"project_id":"x"}');
    expect($public)->not->toContain('project_id');
});

test('retention defaults to the documented window', function () {
    expect($this->settings->getRetentionDays())->toBe(Settings::DEFAULT_RETENTION_DAYS);
});

test('retention can be set to keep indefinitely', function () {
    // Zero is a deliberate choice on the settings screen, not an
    // unset value, and the sweep reads it as "do nothing".
    $this->settings->setRetentionDays(0);

    expect($this->settings->getRetentionDays())->toBe(0);
});

test('a negative retention is not stored as negative', function () {
    // A negative window would make the sweep's cut-off a time in the
    // future, which deletes everything.
    $this->settings->setRetentionDays(-30);

    expect($this->settings->getRetentionDays())->toBeGreaterThanOrEqual(0);
});

test('committee sending from the app is off until it is turned on', function () {
    // A handset writing to a whole committee is a decision the
    // intergroup makes, not a default it inherits.
    expect($this->settings->allowsCommitteeSendFromApp())->toBeFalse();

    $this->settings->setCommitteeSendFromApp(true);

    expect($this->settings->allowsCommitteeSendFromApp())->toBeTrue();
});
