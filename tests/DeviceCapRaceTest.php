<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Devices\Device;
use Fellowship\Tests\Support\InMemoryDeviceRepository;

/**
 * The per-member device cap under concurrency.
 *
 * The cap was `count(findByMemberEmail()) >= MAX` followed by `create()`,
 * with nothing atomic in between, so simultaneous enrolments from one member
 * could all pass the count and land. Each row is "a credential and a push
 * target", and the cap exists specifically to bound a retry loop — the case
 * most likely to race it.
 *
 * keepIfWithinCap() decides by *rank*: how many live rows the member has at
 * or below this row's id. That is a property of the one row rather than of
 * the table at the moment it is asked, which is what makes it safe when two
 * of these run at once — a plain re-count would have every racing row see
 * the same over-cap total and every one of them delete itself.
 *
 * A single-threaded test cannot stage that directly. What it can show is the
 * observable difference the two produce even sequentially: with rank the
 * earliest racer keeps the slot, with a re-count the last one does. See
 * a_race_past_the_cap_keeps_exactly_the_cap().
 */

const DEVICE_CAP_RACE_MAX = 5;

test('a row within the cap survives', function () {
    $repo = new InMemoryDeviceRepository();
    $device = deviceCapRaceEnrol($repo, 'a@example.com');

    expect($repo->keepIfWithinCap($device->id, 'a@example.com', DEVICE_CAP_RACE_MAX))->toBeTrue();
    expect($repo->findByMemberEmail('a@example.com'))->toHaveCount(1);
});

test('the surplus row removes itself', function () {
    $repo = new InMemoryDeviceRepository();

    for ($i = 0; $i < DEVICE_CAP_RACE_MAX; $i++) {
        $kept = deviceCapRaceEnrol($repo, 'a@example.com');
        expect($repo->keepIfWithinCap($kept->id, 'a@example.com', DEVICE_CAP_RACE_MAX))->toBeTrue();
    }

    $surplus = deviceCapRaceEnrol($repo, 'a@example.com');

    expect($repo->keepIfWithinCap($surplus->id, 'a@example.com', DEVICE_CAP_RACE_MAX))->toBeFalse();
    expect($repo->findByMemberEmail('a@example.com'))->toHaveCount(DEVICE_CAP_RACE_MAX);
});

test('a race past the cap keeps exactly the cap', function () {
    // The finding itself: both requests read a count of four, both pass
    // the pre-check, and both write. Modelled by doing every create
    // first and only then letting each row decide — which is the worst
    // possible interleaving.
    $repo = new InMemoryDeviceRepository();

    for ($i = 0; $i < 4; $i++) {
        $existing = deviceCapRaceEnrol($repo, 'a@example.com');
        $repo->keepIfWithinCap($existing->id, 'a@example.com', DEVICE_CAP_RACE_MAX);
    }

    $racers = [
        deviceCapRaceEnrol($repo, 'a@example.com'),
        deviceCapRaceEnrol($repo, 'a@example.com'),
        deviceCapRaceEnrol($repo, 'a@example.com'),
    ];

    $survivors = [];
    foreach ($racers as $racer) {
        if ($repo->keepIfWithinCap($racer->id, 'a@example.com', DEVICE_CAP_RACE_MAX)) {
            $survivors[] = $racer->id;
        }
    }

    expect($survivors)->toHaveCount(1, 'Exactly one racer should fit the remaining slot.');
    expect($repo->findByMemberEmail('a@example.com'))->toHaveCount(DEVICE_CAP_RACE_MAX, 'The cap is met exactly — not undershot by everyone deleting.');

    // The assertion that distinguishes rank from a plain re-count, and
    // the reason it is worth the extra query. Rank is a property of the
    // row, so the *earliest* racer keeps the slot and the later ones
    // stand down. A re-count decides by evaluation order instead: each
    // caller sees the running total, so the first two delete themselves
    // and the last one survives — the newest wins, which is backwards,
    // and under genuine concurrency they would all see the same
    // over-cap total and all delete.
    expect($survivors[0])->toBe($racers[0]->id, 'The first racer through should keep the slot, not the last.');
});

test('one members devices do not count against another', function () {
    $repo = new InMemoryDeviceRepository();

    for ($i = 0; $i < DEVICE_CAP_RACE_MAX; $i++) {
        $d = deviceCapRaceEnrol($repo, 'a@example.com');
        $repo->keepIfWithinCap($d->id, 'a@example.com', DEVICE_CAP_RACE_MAX);
    }

    $other = deviceCapRaceEnrol($repo, 'b@example.com');

    expect($repo->keepIfWithinCap($other->id, 'b@example.com', DEVICE_CAP_RACE_MAX))->toBeTrue();
});

test('a revoked device frees its slot', function () {
    $repo = new InMemoryDeviceRepository();

    $first = deviceCapRaceEnrol($repo, 'a@example.com');
    for ($i = 1; $i < DEVICE_CAP_RACE_MAX; $i++) {
        $d = deviceCapRaceEnrol($repo, 'a@example.com');
        $repo->keepIfWithinCap($d->id, 'a@example.com', DEVICE_CAP_RACE_MAX);
    }

    $repo->revoke($first->id, time());

    $replacement = deviceCapRaceEnrol($repo, 'a@example.com');
    expect($repo->keepIfWithinCap($replacement->id, 'a@example.com', DEVICE_CAP_RACE_MAX))->toBeTrue('Removing a device must let the member enrol another.');
});

function deviceCapRaceEnrol(InMemoryDeviceRepository $repo, string $email): Device
{
    static $n = 0;
    $n++;

    return $repo->create(
        'hash-' . $n,
        $email,
        7,
        'Handset ' . $n,
        'android',
        'public-key',
        'fcm',
        'push-token-' . $n,
        time(),
    );
}
