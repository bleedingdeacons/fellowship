<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Tests\Support\InMemoryDeviceRepository;
use PHPUnit\Framework\TestCase;

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
final class DeviceCapRaceTest extends TestCase
{
    private const MAX = 5;

    /** @test */
    public function a_row_within_the_cap_survives(): void
    {
        $repo = new InMemoryDeviceRepository();
        $device = $this->enrol($repo, 'a@example.com');

        $this->assertTrue($repo->keepIfWithinCap($device->id, 'a@example.com', self::MAX));
        $this->assertCount(1, $repo->findByMemberEmail('a@example.com'));
    }

    /** @test */
    public function the_surplus_row_removes_itself(): void
    {
        $repo = new InMemoryDeviceRepository();

        for ($i = 0; $i < self::MAX; $i++) {
            $kept = $this->enrol($repo, 'a@example.com');
            $this->assertTrue($repo->keepIfWithinCap($kept->id, 'a@example.com', self::MAX));
        }

        $surplus = $this->enrol($repo, 'a@example.com');

        $this->assertFalse($repo->keepIfWithinCap($surplus->id, 'a@example.com', self::MAX));
        $this->assertCount(self::MAX, $repo->findByMemberEmail('a@example.com'));
    }

    /**
     * @test
     */
    public function a_race_past_the_cap_keeps_exactly_the_cap(): void
    {
        // The finding itself: both requests read a count of four, both pass
        // the pre-check, and both write. Modelled by doing every create
        // first and only then letting each row decide — which is the worst
        // possible interleaving.
        $repo = new InMemoryDeviceRepository();

        for ($i = 0; $i < 4; $i++) {
            $existing = $this->enrol($repo, 'a@example.com');
            $repo->keepIfWithinCap($existing->id, 'a@example.com', self::MAX);
        }

        $racers = [
            $this->enrol($repo, 'a@example.com'),
            $this->enrol($repo, 'a@example.com'),
            $this->enrol($repo, 'a@example.com'),
        ];

        $survivors = [];
        foreach ($racers as $racer) {
            if ($repo->keepIfWithinCap($racer->id, 'a@example.com', self::MAX)) {
                $survivors[] = $racer->id;
            }
        }

        $this->assertCount(1, $survivors, 'Exactly one racer should fit the remaining slot.');
        $this->assertCount(
            self::MAX,
            $repo->findByMemberEmail('a@example.com'),
            'The cap is met exactly — not undershot by everyone deleting.'
        );

        // The assertion that distinguishes rank from a plain re-count, and
        // the reason it is worth the extra query. Rank is a property of the
        // row, so the *earliest* racer keeps the slot and the later ones
        // stand down. A re-count decides by evaluation order instead: each
        // caller sees the running total, so the first two delete themselves
        // and the last one survives — the newest wins, which is backwards,
        // and under genuine concurrency they would all see the same
        // over-cap total and all delete.
        $this->assertSame(
            $racers[0]->id,
            $survivors[0],
            'The first racer through should keep the slot, not the last.'
        );
    }

    /** @test */
    public function one_members_devices_do_not_count_against_another(): void
    {
        $repo = new InMemoryDeviceRepository();

        for ($i = 0; $i < self::MAX; $i++) {
            $d = $this->enrol($repo, 'a@example.com');
            $repo->keepIfWithinCap($d->id, 'a@example.com', self::MAX);
        }

        $other = $this->enrol($repo, 'b@example.com');

        $this->assertTrue($repo->keepIfWithinCap($other->id, 'b@example.com', self::MAX));
    }

    /** @test */
    public function a_revoked_device_frees_its_slot(): void
    {
        $repo = new InMemoryDeviceRepository();

        $first = $this->enrol($repo, 'a@example.com');
        for ($i = 1; $i < self::MAX; $i++) {
            $d = $this->enrol($repo, 'a@example.com');
            $repo->keepIfWithinCap($d->id, 'a@example.com', self::MAX);
        }

        $repo->revoke($first->id, time());

        $replacement = $this->enrol($repo, 'a@example.com');
        $this->assertTrue(
            $repo->keepIfWithinCap($replacement->id, 'a@example.com', self::MAX),
            'Removing a device must let the member enrol another.'
        );
    }

    private function enrol(InMemoryDeviceRepository $repo, string $email): \Fellowship\Devices\Device
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
}
