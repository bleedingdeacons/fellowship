<?php

declare(strict_types=1);

namespace Fellowship\Devices;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Storage for enrolled handsets.
 *
 * An interface rather than the wpdb class directly so the REST
 * controllers and the dispatcher can be tested without a database, which
 * is most of what they do.
 */
interface DeviceRepository
{
    /**
     * Enrol a handset.
     *
     * $tokenHash is the HMAC of the bearer token, never the token; the raw
     * value is returned to the app once and then unrecoverable.
     * $publicKey is the normalised base64 SPKI from
     * {@see \Fellowship\Crypto\DevicePublicKey::normalise()} — the caller
     * normalises, because a key that will not load must fail enrolment
     * rather than be stored.
     *
     * @throws \RuntimeException When the row could not be written. Never
     *         returns a Device the caller could mint a token against while
     *         nothing exists to authenticate it — see the implementation
     *         for why silence is the one failure this cannot afford.
     */
    public function create(
        string $tokenHash,
        string $memberEmail,
        int $memberId,
        string $label,
        string $platform,
        string $publicKey,
        string $pushProvider,
        string $pushToken,
        int $now,
    ): Device;

    /**
     * Keep a freshly created device only if it is within the per-member cap,
     * deleting it otherwise. Returns whether it survived.
     *
     * The cap was a read-then-write: findByMemberEmail() was counted, then
     * create() was called, with nothing atomic in between — so concurrent
     * enrolments from one member could all pass the count and land, leaving
     * more rows than the cap allows. Each row is, as DeviceAuthController's
     * docblock says, "a credential and a push target", and the cap exists
     * specifically to bound a retry loop, which is the case most likely to
     * race it.
     *
     * Decided by rank rather than by re-counting: the implementation asks
     * how many live rows this member has with an id at or below this one,
     * which is a property of this row alone. Two rows racing past a cap of
     * five each compute their own rank, the sixth deletes itself and the
     * fifth stays — where a plain re-count would have both see six and both
     * delete.
     */
    public function keepIfWithinCap(int $deviceId, string $memberEmail, int $max): bool;

    /** Live devices only; a revoked row is never returned. */
    public function findByTokenHash(string $tokenHash): ?Device;

    /** Any device, revoked or not — for the admin list. */
    public function findById(int $id): ?Device;

    /**
     * Live devices enrolled to one member.
     *
     * @return list<Device>
     */
    public function findByMemberEmail(string $memberEmail): array;

    /**
     * Every live device, for a message addressed to the whole fellowship.
     *
     * @return list<Device>
     */
    public function findAllLive(): array;

    /**
     * One page of devices for the admin list, revoked ones included.
     *
     * @return list<Device>
     */
    public function list(int $limit, int $offset): array;

    public function countAll(): int;

    public function touchLastSeen(int $id, int $now): void;

    public function updatePush(int $id, string $pushProvider, string $pushToken): void;

    /**
     * Replace a handset's public key.
     *
     * Its keypair is regenerated when the platform invalidates the old one
     * — a changed screen lock, a restored backup — and the handset has to
     * be able to say so without re-enrolling and losing its place in the
     * device list.
     */
    public function updatePublicKey(int $id, string $publicKey): bool;

    public function markKeyFault(int $id, int $now): void;

    public function clearKeyFault(int $id): void;

    public function revoke(int $id, int $now): bool;

    /** Revoke every device belonging to one member, e.g. on member deletion. */
    public function revokeAllForMember(string $memberEmail, int $now): int;

    /** Delete a row outright. Revoking is usually what is wanted instead. */
    public function remove(int $id): bool;
}
