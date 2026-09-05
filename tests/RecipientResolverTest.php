<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Core\Cipher;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
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
 *
 * @covers \Fellowship\Messaging\RecipientResolver
 * @covers \Fellowship\Core\Cipher
 */
final class RecipientResolverTest extends TestCase
{
    private InMemoryMemberRepository $members;
    private InMemoryCommitteeRepository $committees;

    protected function setUp(): void
    {
        parent::setUp();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
            new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
            new MemberStub(id: 9, anonymousName: 'No Address', personalEmail: ''),
        ]);

        $this->committees = new InMemoryCommitteeRepository();
    }

    public function testNamedMembersAreResolvedToAddresses(): void
    {
        $resolved = $this->resolve(['member_emails' => ['dave@example.org', 'sue@example.org']]);

        self::assertCount(2, $resolved);
        self::assertSame('dave@example.org', $resolved[0]['email']);
        self::assertSame(7, $resolved[0]['member_id']);
    }

    public function testTheSenderIsNeverARecipientOfTheirOwnMessage(): void
    {
        // A copy of your own message arriving on your own handset reads
        // as a bug to whoever receives it.
        $resolved = $this->resolve(
            ['member_emails' => ['dave@example.org', 'sue@example.org']],
            sender: 'dave@example.org',
        );

        self::assertCount(1, $resolved);
        self::assertSame('sue@example.org', $resolved[0]['email']);
    }

    public function testTheSenderIsMatchedWithoutRegardToCase(): void
    {
        $resolved = $this->resolve(
            ['member_emails' => ['dave@example.org']],
            sender: '  Dave@Example.ORG ',
        );

        self::assertSame([], $resolved);
    }

    public function testAMemberNamedTwiceGetsOneCopy(): void
    {
        // The realistic case is a member on two branches of a committee
        // tree; the same guard covers a caller that repeats an address.
        $resolved = $this->resolve([
            'member_emails' => ['dave@example.org', 'dave@example.org', 'DAVE@example.org'],
        ]);

        self::assertCount(1, $resolved);
    }

    public function testAMemberWithNoAddressIsDroppedFromABroadcast(): void
    {
        // Naming nobody is not "nobody": it is the whole fellowship, which
        // is what the admin broadcast path does. What this asserts is that
        // the gate still runs inside it -- the member with no address is
        // absent, because a recipient row with an empty address is one
        // nothing can ever be delivered against.
        $resolved = $this->resolve([]);

        self::assertCount(2, $resolved);
        self::assertSame(
            ['dave@example.org', 'sue@example.org'],
            array_column($resolved, 'email'),
        );
    }

    public function testAnAddressThatIsNotAMembersResolvesToNobody(): void
    {
        // Recipients come from Unity, never from the caller. An address
        // nobody holds is not somebody to deliver to.
        $resolved = $this->resolve(['member_emails' => ['stranger@example.org']]);

        self::assertSame([], $resolved);
    }

    public function testAnEmptyCommitteeResolvesToNobody(): void
    {
        $resolved = $this->resolve(['committee' => 'nobody-is-on-this']);

        self::assertSame([], $resolved);
    }

    // ── The secret store ──────────────────────────────────────────────

    public function testASecretSurvivesTheRoundTrip(): void
    {
        $cipher = new Cipher('fellowship-secrets');

        $stored = $cipher->encrypt('a-client-secret');

        self::assertNotSame('a-client-secret', $stored);
        self::assertStringNotContainsString('a-client-secret', $stored);
        self::assertSame('a-client-secret', $cipher->decrypt($stored));
    }

    public function testTheSameSecretEncryptsDifferentlyEachTime(): void
    {
        // A fresh nonce per encryption. Identical ciphertext for
        // identical input would tell anybody reading the options table
        // that two providers share a secret.
        $cipher = new Cipher('fellowship-secrets');

        self::assertNotSame($cipher->encrypt('same'), $cipher->encrypt('same'));
    }

    public function testASecretFromAnotherDomainWillNotOpen(): void
    {
        // The domain separates one plugin's stored secrets from another's
        // on the same site.
        $stored = (new Cipher('fellowship-secrets'))->encrypt('a-client-secret');

        self::assertSame('', (new Cipher('somebody-elses-secrets'))->decrypt($stored));
    }

    public function testRubbishDecryptsToNothingRatherThanThrowing(): void
    {
        // A truncated or hand-edited option value must not take the
        // settings screen down.
        $cipher = new Cipher('fellowship-secrets');

        self::assertSame('', $cipher->decrypt(''));
        self::assertSame('', $cipher->decrypt('not-base64!'));
        self::assertSame('', $cipher->decrypt(base64_encode('too short')));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /**
     * @param array<string, mixed> $request
     * @return list<array{email: string, member_id: int}>
     */
    private function resolve(array $request, string $sender = ''): array
    {
        $built = MessageRequest::fromArray(array_merge([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
        ], $request));

        self::assertNotInstanceOf(WP_Error::class, $built);

        $resolver = new RecipientResolver(
            $this->members,
            $this->committees,
            new MemberGate($this->members),
        );

        return $resolver->resolve($built, $sender);
    }
}
