<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
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
 *
 * @covers \Fellowship\Devices\WpdbDeviceRepository
 */
final class WpdbDeviceRepositoryTest extends TestCase
{
    private RecordingWpdb $wpdb;
    private WpdbDeviceRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->wpdb = new RecordingWpdb();
        $this->repository = new WpdbDeviceRepository($this->wpdb);
    }

    // ── Enrolling ─────────────────────────────────────────────────────

    public function testEnrollingWritesEveryColumnAndAnswersTheNewRow(): void
    {
        $this->wpdb->insert_id = 4;

        $device = $this->create();

        self::assertSame(4, $device->id);
        self::assertSame('member@example.org', $device->memberEmail);
        self::assertCount(1, $this->wpdb->inserts);

        $written = $this->wpdb->inserts[0]['data'];
        self::assertSame('hash-1', $written['token_hash']);
        self::assertSame('android', $written['platform']);

        // Enrolled and last seen at the same moment: a handset that has
        // never called again should not read as stale on the day it
        // arrived.
        self::assertSame($written['created_at'], $written['last_seen_at']);
    }

    public function testTheRawTokenIsNeverWritten(): void
    {
        // The column holds an HMAC. If the token itself were stored, a
        // database dump would be a set of working credentials.
        $this->wpdb->insert_id = 4;

        $this->create();

        self::assertArrayNotHasKey('token', $this->wpdb->inserts[0]['data']);
        self::assertSame('hash-1', $this->wpdb->inserts[0]['data']['token_hash']);
    }

    public function testAnInsertThatFailsThrowsRatherThanAnsweringIdZero(): void
    {
        $this->wpdb->results = [];
        $this->wpdb->insertResult = false;

        $this->expectException(RuntimeException::class);

        $this->create();
    }

    public function testAnInsertThatReportsNoIdAlsoThrows(): void
    {
        // A missing table can succeed and still leave insert_id at 0.
        $this->wpdb->insert_id = 0;

        $this->expectException(RuntimeException::class);

        $this->create();
    }

    // ── Looking one up ────────────────────────────────────────────────

    public function testATokenLookupExcludesRevokedRowsInTheQueryItself(): void
    {
        $this->wpdb->results = [$this->row()];

        $device = $this->repository->findByTokenHash('hash-1');

        self::assertNotNull($device);
        self::assertStringContainsString('revoked_at IS NULL', $this->wpdb->lastQuery());
    }

    public function testAMemberLookupAlsoExcludesRevokedRows(): void
    {
        $this->wpdb->results = [$this->row()];

        $this->repository->findByMemberEmail('member@example.org');

        self::assertStringContainsString('revoked_at IS NULL', $this->wpdb->lastQuery());
    }

    public function testTheFanOutListAlsoExcludesRevokedRows(): void
    {
        // This one feeds message delivery. A revoked handset appearing
        // here would be sent messages it should no longer receive.
        $this->wpdb->results = [$this->row()];

        $this->repository->findAllLive();

        self::assertStringContainsString('revoked_at IS NULL', $this->wpdb->lastQuery());
    }

    public function testTheAdminListDeliberatelyDoesNotExcludeThem(): void
    {
        // The one query that must show revoked rows: the admin list is
        // where somebody confirms a handset was cut off.
        $this->wpdb->results = [$this->row()];

        $this->repository->list(25, 0);

        self::assertStringNotContainsString('revoked_at IS NULL', $this->wpdb->lastQuery());
    }

    public function testLookingUpByIdFindsARevokedRow(): void
    {
        // Also deliberate: the admin screen resolves a device by id to
        // act on it, including one already revoked.
        $this->wpdb->results = [$this->row(['revoked_at' => 1788000500])];

        $device = $this->repository->findById(4);

        self::assertNotNull($device);
        self::assertTrue($device->isRevoked());
    }

    public function testAnUnknownTokenAnswersNull(): void
    {
        $this->wpdb->results = [];

        self::assertNull($this->repository->findByTokenHash('nobody'));
    }

    public function testAnAddressIsLoweredAndTrimmedBeforeItIsMatched(): void
    {
        // Addresses arrive from an ID token, from a form and from the
        // member record, and only one of those is reliably normalised.
        $this->wpdb->results = [];

        $this->repository->findByMemberEmail('  Member@Example.ORG ');

        self::assertStringContainsString('member@example.org', $this->wpdb->lastQuery());
    }

    // ── Reading a row back ────────────────────────────────────────────

    public function testARowBecomesADevice(): void
    {
        $this->wpdb->results = [$this->row()];

        $device = $this->repository->findById(4);

        self::assertNotNull($device);
        self::assertSame(4, $device->id);
        self::assertSame(7, $device->memberId);
        self::assertSame('Pixel 6a', $device->label);
        self::assertFalse($device->isRevoked());
        self::assertFalse($device->hasKeyFault());
    }

    public function testAKeyFaultOnTheRowIsReadBack(): void
    {
        $this->wpdb->results = [$this->row(['key_fault_at' => 1788000900])];

        $device = $this->repository->findById(4);

        self::assertNotNull($device);
        self::assertTrue($device->hasKeyFault());
    }

    public function testARowWithMissingColumnsDoesNotFatal(): void
    {
        // A schema that has moved on underneath should degrade rather
        // than take the admin screen down.
        $this->wpdb->results = [['id' => 4]];

        $device = $this->repository->findById(4);

        self::assertNotNull($device);
        self::assertSame('', $device->memberEmail);
    }

    // ── Changing one ──────────────────────────────────────────────────

    public function testRevokingStampsTheRow(): void
    {
        $this->wpdb->updateResult = 1;

        self::assertTrue($this->repository->revoke(4, 1788000500));
        self::assertSame(1788000500, $this->wpdb->updates[0]['data']['revoked_at']);
    }

    public function testRevokingSomethingAlreadyRevokedChangesNothing(): void
    {
        // 0 rows affected. Reported as false so the caller does not write
        // an audit entry for a revocation that did not happen.
        $this->wpdb->updateResult = 0;

        self::assertFalse($this->repository->revoke(4, 1788000500));
    }

    public function testRevokingEveryDeviceForAMemberAnswersHowMany(): void
    {
        $this->wpdb->queryResult = 3;

        self::assertSame(3, $this->repository->revokeAllForMember('member@example.org', 1788000500));
    }

    public function testRotatingTheKeyAlsoClearsTheFault(): void
    {
        // The handset presenting a new key is the only way the server
        // ever learns it can read again.
        $this->wpdb->updateResult = 1;

        self::assertTrue($this->repository->updatePublicKey(4, 'new-spki'));

        $written = $this->wpdb->updates[0]['data'];
        self::assertSame('new-spki', $written['public_key']);
        self::assertNull($written['key_fault_at']);
    }

    public function testAKeyFaultIsStamped(): void
    {
        $this->wpdb->updateResult = 1;

        $this->repository->markKeyFault(4, 1788000900);

        self::assertSame(1788000900, $this->wpdb->updates[0]['data']['key_fault_at']);
    }

    public function testAPushTokenIsReplaced(): void
    {
        $this->wpdb->updateResult = 1;

        $this->repository->updatePush(4, 'fcm', 'token-2');

        self::assertSame('token-2', $this->wpdb->updates[0]['data']['push_token']);
    }

    public function testLastSeenIsStamped(): void
    {
        $this->wpdb->updateResult = 1;

        $this->repository->touchLastSeen(4, 1788001000);

        self::assertSame(1788001000, $this->wpdb->updates[0]['data']['last_seen_at']);
    }

    public function testRemovingDeletesTheRow(): void
    {
        $this->wpdb->deleteResult = 1;

        self::assertTrue($this->repository->remove(4));
        self::assertCount(1, $this->wpdb->deletes);
    }

    public function testCountingReadsASingleValue(): void
    {
        $this->wpdb->results = [];
        $this->wpdb->var = 12;

        self::assertSame(12, $this->repository->countAll());
    }

    public function testTheTableNameIsBuiltFromThePrefix(): void
    {
        self::assertStringEndsWith('fellowship_devices', WpdbDeviceRepository::tableName($this->wpdb));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function create(): Device
    {
        return $this->repository->create(
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
    private function row(array $overrides = []): array
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
}
