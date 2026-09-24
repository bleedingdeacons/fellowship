<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Core\Cipher;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;

/**
 * Who a message actually reaches, and the secret store behind the
 * settings screen.
 *
 * <b>Recipients come entirely from Unity.</b> Nothing a caller sends is
 * ever treated as an address to deliver to — a committee slug and a set
 * of member ids are looked up, and every resulting member is put through
 * the same gate the sign-in path uses. So a message cannot be addressed
 * to somebody who is not a member, however it was composed.
 *
 * Three properties are asserted that would each fail silently:
 *
 *  - the sender is excluded, because a copy of your own message arriving
 *    on your own handset reads as a bug;
 *  - recipients are deduped by address, so a member sitting on two
 *    branches of a committee tree gets one copy rather than two;
 *  - a member the gate refuses is dropped, not delivered to.
 */

covers(\Fellowship\Messaging\RecipientResolver::class, \Fellowship\Core\Cipher::class);

beforeEach(function () {
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
        new MemberStub(id: 9, anonymousName: 'No Address', personalEmail: ''),
    ]);

    $this->committees = new InMemoryCommitteeRepository();
});

test('named members are resolved to addresses', function () {
    $resolved = recipientResolverResolve(['member_emails' => ['dave@example.org', 'sue@example.org']]);

    expect($resolved)->toHaveCount(2);
    expect($resolved[0]['email'])->toBe('dave@example.org');
    expect($resolved[0]['member_id'])->toBe(7);
});

test('the sender is never a recipient of their own message', function () {
    // A copy of your own message arriving on your own handset reads
    // as a bug to whoever receives it.
    $resolved = recipientResolverResolve(
        ['member_emails' => ['dave@example.org', 'sue@example.org']],
        sender: 'dave@example.org',
    );

    expect($resolved)->toHaveCount(1);
    expect($resolved[0]['email'])->toBe('sue@example.org');
});

test('the sender is matched without regard to case', function () {
    $resolved = recipientResolverResolve(
        ['member_emails' => ['dave@example.org']],
        sender: '  Dave@Example.ORG ',
    );

    expect($resolved)->toBe([]);
});

test('a member named twice gets one copy', function () {
    // The realistic case is a member on two branches of a committee
    // tree; the same guard covers a caller that repeats an address.
    $resolved = recipientResolverResolve([
        'member_emails' => ['dave@example.org', 'dave@example.org', 'DAVE@example.org'],
    ]);

    expect($resolved)->toHaveCount(1);
});

test('a member with no address is dropped from a broadcast', function () {
    // Naming nobody is not "nobody": it is the whole fellowship, which
    // is what the admin broadcast path does. What this asserts is that
    // the gate still runs inside it -- the member with no address is
    // absent, because a recipient row with an empty address is one
    // nothing can ever be delivered against.
    $resolved = recipientResolverResolve([]);

    expect($resolved)->toHaveCount(2);
    expect(array_column($resolved, 'email'))->toBe(['dave@example.org', 'sue@example.org']);
});

test('an address that is not a members resolves to nobody', function () {
    // Recipients come from Unity, never from the caller. An address
    // nobody holds is not somebody to deliver to.
    $resolved = recipientResolverResolve(['member_emails' => ['stranger@example.org']]);

    expect($resolved)->toBe([]);
});

test('an empty committee resolves to nobody', function () {
    $resolved = recipientResolverResolve(['committee' => 'nobody-is-on-this']);

    expect($resolved)->toBe([]);
});

test('several committees resolve to the union of their members', function () {
    $this->committees = new InMemoryCommitteeRepository(
        [
            new CommitteeStub(id: 2, slug: 'literature', name: 'Literature'),
            new CommitteeStub(id: 3, slug: 'public-information', name: 'Public Information'),
        ],
        ['literature' => [7], 'public-information' => [8]],
    );

    $resolved = recipientResolverResolve(['committees' => ['literature', 'public-information']]);

    expect(array_column($resolved, 'email'))->toBe(['dave@example.org', 'sue@example.org']);
});

test('a committee and named members reach both at once', function () {
    $this->committees = new InMemoryCommitteeRepository(
        [new CommitteeStub(id: 2, slug: 'literature', name: 'Literature')],
        ['literature' => [7]],
    );

    $resolved = recipientResolverResolve([
        'committees'    => ['literature'],
        'member_emails' => ['sue@example.org'],
    ]);

    expect(array_column($resolved, 'email'))->toBe(['dave@example.org', 'sue@example.org']);
});

test('somebody both named and on a committee still gets one copy', function () {
    // The reason mixed audiences are safe to allow: de-duplication
    // was always there, because a member can sit on two branches of
    // one committee tree. Being named as well is the same problem.
    $this->committees = new InMemoryCommitteeRepository(
        [new CommitteeStub(id: 2, slug: 'literature', name: 'Literature')],
        ['literature' => [7]],
    );

    $resolved = recipientResolverResolve([
        'committees'    => ['literature'],
        'member_emails' => ['dave@example.org'],
    ]);

    expect($resolved)->toHaveCount(1);
    expect($resolved[0]['email'])->toBe('dave@example.org');
});

// ── The secret store ──────────────────────────────────────────────

test('a secret survives the round trip', function () {
    $cipher = new Cipher('fellowship-secrets');

    $stored = $cipher->encrypt('a-client-secret');

    expect($stored)->not->toBe('a-client-secret');
    expect($stored)->not->toContain('a-client-secret');
    expect($cipher->decrypt($stored))->toBe('a-client-secret');
});

test('the same secret encrypts differently each time', function () {
    // A fresh nonce per encryption. Identical ciphertext for
    // identical input would tell anybody reading the options table
    // that two providers share a secret.
    $cipher = new Cipher('fellowship-secrets');

    expect($cipher->encrypt('same'))->not->toBe($cipher->encrypt('same'));
});

test('a secret from another domain will not open', function () {
    // The domain separates one plugin's stored secrets from another's
    // on the same site.
    $stored = (new Cipher('fellowship-secrets'))->encrypt('a-client-secret');

    expect((new Cipher('somebody-elses-secrets'))->decrypt($stored))->toBe('');
});

test('rubbish decrypts to nothing rather than throwing', function () {
    // A truncated or hand-edited option value must not take the
    // settings screen down.
    $cipher = new Cipher('fellowship-secrets');

    expect($cipher->decrypt(''))->toBe('');
    expect($cipher->decrypt('not-base64!'))->toBe('');
    expect($cipher->decrypt(base64_encode('too short')))->toBe('');
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * @param array<string, mixed> $request
 * @return list<array{email: string, member_id: int}>
 */
function recipientResolverResolve(array $request, string $sender = ''): array
{
    $built = MessageRequest::fromArray(array_merge([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
    ], $request));

    expect($built)->not->toBeInstanceOf(WP_Error::class);

    $resolver = new RecipientResolver(
        test()->members,
        test()->committees,
        new MemberGate(test()->members),
    );

    return $resolver->resolve($built, $sender);
}
