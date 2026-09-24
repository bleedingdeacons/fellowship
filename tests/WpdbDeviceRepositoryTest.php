<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Devices\Device;
use Fellowship\Tests\Support\RecordingWpdb;
use Fellowship\Devices\WpdbDeviceRepository;
use RuntimeException;

/**
 * The device table: the SQL it writes, and the two things that must never
 * be left to a caller.
 *
 * <b>Revocation is a WHERE clause, not a flag anybody checks.</b> Every
 * lookup that could authenticate a handset carries
 * `revoked_at IS NULL`, so a revoked token is indistinguishable from an
 * invented one at every call site. A future refactor that "simplified"
 * one of those queries and filtered afterwards would leave a revoked
 * handset working until somebody noticed. That is asserted here on the
 * generated SQL, because there is no other place it can be.
 *
 * <b>A failed insert throws.</b> Left unchecked it would answer a Device
 * with id 0, the caller would mint a token against it, and enrolment
 * would return 201 with a working-looking credential for a row that does
 * not exist — a handset that 401s on its next request, an empty admin
 * list, and nothing anywhere saying why.
 */

covers(\Fellowship\Devices\WpdbDeviceRepository::class);

beforeEach(function () {
    $this->wpdb = new RecordingWpdb();
    $this->repository = new WpdbDeviceRepository($this->wpdb);
});

// ── Enrolling ─────────────────────────────────────────────────────

test('enrolling writes every column and answers the new row', function () {
    $this->wpdb->insert_id = 4;

    $device = wpdbDeviceRepositoryCreate();

    expect($device->id)->toBe(4);
    expect($device->memberEmail)->toBe('member@example.org');
    expect($this->wpdb->inserts)->toHaveCount(1);

    $written = $this->wpdb->inserts[0]['data'];
    expect($written['token_hash'])->toBe('hash-1');
    expect($written['platform'])->toBe('android');

    // Enrolled and last seen at the same moment: a handset that has
    // never called again should not read as stale on the day it
    // arrived.
    expect($written['last_seen_at'])->toBe($written['created_at']);
});

test('the raw token is never written', function () {
    // The column holds an HMAC. If the token itself were stored, a
    // database dump would be a set of working credentials.
    $this->wpdb->insert_id = 4;

    wpdbDeviceRepositoryCreate();

    expect($this->wpdb->inserts[0]['data'])->not->toHaveKey('token');
    expect($this->wpdb->inserts[0]['data']['token_hash'])->toBe('hash-1');
});

test('an insert that fails throws rather than answering id zero', function () {
    $this->wpdb->results = [];
    $this->wpdb->insertResult = false;

    wpdbDeviceRepositoryCreate();
})->throws(RuntimeException::class);

test('an insert that reports no id also throws', function () {
    // A missing table can succeed and still leave insert_id at 0.
    $this->wpdb->insert_id = 0;

    wpdbDeviceRepositoryCreate();
})->throws(RuntimeException::class);

// ── Looking one up ────────────────────────────────────────────────

test('a token lookup excludes revoked rows in the query itself', function () {
    $this->wpdb->results = [wpdbDeviceRepositoryRow()];

    $device = $this->repository->findByTokenHash('hash-1');

    expect($device)->not->toBeNull();
    expect($this->wpdb->lastQuery())->toContain('revoked_at IS NULL');
});

test('a member lookup also excludes revoked rows', function () {
    $this->wpdb->results = [wpdbDeviceRepositoryRow()];

    $this->repository->findByMemberEmail('member@example.org');

    expect($this->wpdb->lastQuery())->toContain('revoked_at IS NULL');
});

test('the fan out list also excludes revoked rows', function () {
    // This one feeds message delivery. A revoked handset appearing
    // here would be sent messages it should no longer receive.
    $this->wpdb->results = [wpdbDeviceRepositoryRow()];

    $this->repository->findAllLive();

    expect($this->wpdb->lastQuery())->toContain('revoked_at IS NULL');
});

test('the admin list deliberately does not exclude them', function () {
    // The one query that must show revoked rows: the admin list is
    // where somebody confirms a handset was cut off.
    $this->wpdb->results = [wpdbDeviceRepositoryRow()];

    $this->repository->list(25, 0);

    expect($this->wpdb->lastQuery())->not->toContain('revoked_at IS NULL');
});

test('looking up by id finds a revoked row', function () {
    // Also deliberate: the admin screen resolves a device by id to
    // act on it, including one already revoked.
    $this->wpdb->results = [wpdbDeviceRepositoryRow(['revoked_at' => 1788000500])];

    $device = $this->repository->findById(4);

    expect($device)->not->toBeNull();
    expect($device->isRevoked())->toBeTrue();
});

test('an unknown token answers null', function () {
    $this->wpdb->results = [];

    expect($this->repository->findByTokenHash('nobody'))->toBeNull();
});

test('an address is lowered and trimmed before it is matched', function () {
    // Addresses arrive from an ID token, from a form and from the
    // member record, and only one of those is reliably normalised.
    $this->wpdb->results = [];

    $this->repository->findByMemberEmail('  Member@Example.ORG ');

    expect($this->wpdb->lastQuery())->toContain('member@example.org');
});

// ── Reading a row back ────────────────────────────────────────────

test('a row becomes a device', function () {
    $this->wpdb->results = [wpdbDeviceRepositoryRow()];

    $device = $this->repository->findById(4);

    expect($device)->not->toBeNull();
    expect($device->id)->toBe(4);
    expect($device->memberId)->toBe(7);
    expect($device->label)->toBe('Pixel 6a');
    expect($device->isRevoked())->toBeFalse();
    expect($device->hasKeyFault())->toBeFalse();
});

test('a key fault on the row is read back', function () {
    $this->wpdb->results = [wpdbDeviceRepositoryRow(['key_fault_at' => 1788000900])];

    $device = $this->repository->findById(4);

    expect($device)->not->toBeNull();
    expect($device->hasKeyFault())->toBeTrue();
});

test('a row with missing columns does not fatal', function () {
    // A schema that has moved on underneath should degrade rather
    // than take the admin screen down.
    $this->wpdb->results = [['id' => 4]];

    $device = $this->repository->findById(4);

    expect($device)->not->toBeNull();
    expect($device->memberEmail)->toBe('');
});

// ── Changing one ──────────────────────────────────────────────────

test('revoking stamps the row', function () {
    $this->wpdb->updateResult = 1;

    expect($this->repository->revoke(4, 1788000500))->toBeTrue();
    expect($this->wpdb->updates[0]['data']['revoked_at'])->toBe(1788000500);
});

test('revoking something already revoked changes nothing', function () {
    // 0 rows affected. Reported as false so the caller does not write
    // an audit entry for a revocation that did not happen.
    $this->wpdb->updateResult = 0;

    expect($this->repository->revoke(4, 1788000500))->toBeFalse();
});

test('revoking every device for a member answers how many', function () {
    $this->wpdb->queryResult = 3;

    expect($this->repository->revokeAllForMember('member@example.org', 1788000500))->toBe(3);
});

test('rotating the key also clears the fault', function () {
    // The handset presenting a new key is the only way the server
    // ever learns it can read again.
    $this->wpdb->updateResult = 1;

    expect($this->repository->updatePublicKey(4, 'new-spki'))->toBeTrue();

    $written = $this->wpdb->updates[0]['data'];
    expect($written['public_key'])->toBe('new-spki');
    expect($written['key_fault_at'])->toBeNull();
});

test('a key fault is stamped', function () {
    $this->wpdb->updateResult = 1;

    $this->repository->markKeyFault(4, 1788000900);

    expect($this->wpdb->updates[0]['data']['key_fault_at'])->toBe(1788000900);
});

test('a push token is replaced', function () {
    $this->wpdb->updateResult = 1;

    $this->repository->updatePush(4, 'fcm', 'token-2');

    expect($this->wpdb->updates[0]['data']['push_token'])->toBe('token-2');
});

test('last seen is stamped', function () {
    $this->wpdb->updateResult = 1;

    $this->repository->touchLastSeen(4, 1788001000);

    expect($this->wpdb->updates[0]['data']['last_seen_at'])->toBe(1788001000);
});

test('removing deletes the row', function () {
    $this->wpdb->deleteResult = 1;

    expect($this->repository->remove(4))->toBeTrue();
    expect($this->wpdb->deletes)->toHaveCount(1);
});

test('counting reads a single value', function () {
    $this->wpdb->results = [];
    $this->wpdb->var = 12;

    expect($this->repository->countAll())->toBe(12);
});

test('the table name is built from the prefix', function () {
    expect(WpdbDeviceRepository::tableName($this->wpdb))->toEndWith('fellowship_devices');
});

// ── Fixtures ──────────────────────────────────────────────────────

function wpdbDeviceRepositoryCreate(): Device
{
    return test()->repository->create(
        'hash-1',
        'member@example.org',
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );
}

/**
 * @param array<string, mixed> $overrides
 * @return array<string, mixed>
 */
function wpdbDeviceRepositoryRow(array $overrides = []): array
{
    return array_merge([
        'id'            => 4,
        'member_email'  => 'member@example.org',
        'member_id'     => 7,
        'label'         => 'Pixel 6a',
        'platform'      => 'android',
        'public_key'    => 'spki',
        'push_provider' => 'fcm',
        'push_token'    => 'token-1',
        'created_at'    => 1788000000,
        'last_seen_at'  => 1788000100,
        'revoked_at'    => null,
        'key_fault_at'  => null,
    ], $overrides);
}
