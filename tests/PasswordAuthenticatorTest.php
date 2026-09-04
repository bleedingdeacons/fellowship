<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\PasswordResetResult;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use BleedingDeacons\WpMocks\TestCase;
use Unity\Members\Interfaces\Member;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Password sign-in: the second way into Link, and the only one where
 * this server holds the secret.
 *
 * <b>Most of what is asserted here is a refusal.</b> Every OAuth path
 * hands verification to somebody else; this one does it itself, so the
 * failure modes are ours. The ones that matter are quiet: an account
 * that can be enumerated, a lockout that never engages, a reset link
 * that works twice.
 *
 * Password is deliberately not the default path — four providers come
 * first in the app, and a member only has a password if they asked for
 * one — which makes it exactly the sort of code that rots unnoticed.
 */
final class PasswordAuthenticatorTest extends TestCase
{
    private const MEMBER = 'member@example.org';
    private const STRANGER = 'nobody@example.org';
    private const GOOD_PASSWORD = 'correct horse battery staple';

    private InMemoryPasswordCredentialRepository $credentials;
    private PasswordAuthenticator $auth;
    private PasswordResetMailer $mailer;
    private int $now;

    protected function setUp(): void
    {
        parent::setUp();

        $this->now = 1_800_000_000;
        $this->credentials = new InMemoryPasswordCredentialRepository();

        $this->mailer = new PasswordResetMailer();

        $this->auth = new PasswordAuthenticator(
            $this->credentials,
            new MemberGate($this->members()),
            $this->mailer,
            new PasswordPolicy(),
        );
    }

    // ── Signing in ────────────────────────────────────────────────────

    public function testACorrectPasswordProvesTheAddress(): void
    {
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        $identity = $this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now);

        self::assertNotNull($identity);
        self::assertSame(self::MEMBER, $identity->email);
        self::assertSame('password', $identity->provider);
    }

    public function testTheAddressIsNormalisedBeforeItIsMatched(): void
    {
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        self::assertNotNull($this->auth->attemptLogin('  Member@Example.ORG ', self::GOOD_PASSWORD, $this->now));
    }

    public function testAWrongPasswordIsRefused(): void
    {
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        self::assertNull($this->auth->attemptLogin(self::MEMBER, 'not the password', $this->now));
    }

    public function testAnAddressWithNoPasswordIsRefused(): void
    {
        // The normal state of affairs: passwords are set only on request,
        // so most members never have one.
        self::assertNull($this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now));
    }

    public function testGuessingAtAnUnknownAddressCreatesNoRow(): void
    {
        // Otherwise the table becomes a list of every address anybody has
        // ever tried, and a lockout could be induced for an address that
        // has no account at all.
        $this->auth->attemptLogin(self::STRANGER, 'anything', $this->now);

        self::assertSame([], $this->credentials->rows);
    }

    // ── Lockout ───────────────────────────────────────────────────────

    public function testFiveWrongPasswordsLockTheAccount(): void
    {
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
            self::assertNull($this->auth->attemptLogin(self::MEMBER, 'wrong', $this->now));
        }

        // The telling assertion: the *right* password is now refused too.
        // A lockout that let the correct password through would stop
        // nothing, since that is what the attacker is searching for.
        self::assertNull($this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now));
    }

    public function testTheLockoutExpires(): void
    {
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
            $this->auth->attemptLogin(self::MEMBER, 'wrong', $this->now);
        }

        $later = $this->now + PasswordAuthenticator::LOCKOUT_SECONDS + 1;

        self::assertNotNull($this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $later));
    }

    public function testASuccessfulLoginClearsTheFailureCount(): void
    {
        // Without this a member who mistypes four times over a month,
        // signing in successfully between each, is locked out by the
        // fifth — a counter that only ever climbs.
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS - 1; $i++) {
            $this->auth->attemptLogin(self::MEMBER, 'wrong', $this->now);
        }

        self::assertNotNull($this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now));
        self::assertSame(0, $this->credentials->rows[self::MEMBER]->failedAttempts);
    }

    // ── Asking for a link ─────────────────────────────────────────────

    public function testARequestForAMemberStoresAHashedToken(): void
    {
        $this->auth->beginReset(self::MEMBER, $this->now);

        $row = $this->credentials->rows[self::MEMBER] ?? null;
        self::assertNotNull($row);
        self::assertNotSame('', $row->resetTokenHash);
        self::assertSame(64, strlen($row->resetTokenHash), 'The stored token must be a SHA-256 hex digest.');
        self::assertSame($this->now + PasswordAuthenticator::RESET_TTL_SECONDS, $row->resetExpiresAt);
    }

    public function testARequestForAStrangerDoesNothingAtAll(): void
    {
        // The endpoint answers identically either way, so this is what
        // stops the *database* becoming the thing that reveals who is a
        // member.
        $this->auth->beginReset(self::STRANGER, $this->now);

        self::assertSame([], $this->credentials->rows);
    }

    public function testASecondRequestInsideTheCooldownIsIgnored(): void
    {
        $this->auth->beginReset(self::MEMBER, $this->now);
        $first = $this->credentials->rows[self::MEMBER]->resetTokenHash;

        $this->auth->beginReset(self::MEMBER, $this->now + 5);

        self::assertSame(
            $first,
            $this->credentials->rows[self::MEMBER]->resetTokenHash,
            'A second request inside the cooldown must not mint a new token, or a nuisance actor can flood an inbox.',
        );
    }

    public function testARequestAfterTheCooldownIssuesAFreshToken(): void
    {
        $this->auth->beginReset(self::MEMBER, $this->now);
        $first = $this->credentials->rows[self::MEMBER]->resetTokenHash;

        $this->auth->beginReset(self::MEMBER, $this->now + PasswordAuthenticator::RESET_COOLDOWN_SECONDS + 1);

        self::assertNotSame($first, $this->credentials->rows[self::MEMBER]->resetTokenHash);
    }

    // ── Completing one ────────────────────────────────────────────────

    public function testAValidTokenSetsThePassword(): void
    {
        $token = $this->requestLink(self::MEMBER);

        $result = $this->auth->completeReset($token, self::GOOD_PASSWORD, $this->now);

        self::assertTrue($result->isOk());
        self::assertNotNull($this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now));
    }

    public function testATokenIsSingleUse(): void
    {
        $token = $this->requestLink(self::MEMBER);

        self::assertTrue($this->auth->completeReset($token, self::GOOD_PASSWORD, $this->now)->isOk());

        $second = $this->auth->completeReset($token, 'another perfectly fine passphrase', $this->now);

        self::assertSame(PasswordResetResult::INVALID_TOKEN, $second->status);
        self::assertNotNull(
            $this->auth->attemptLogin(self::MEMBER, self::GOOD_PASSWORD, $this->now),
            'The first password must still stand after the replay is refused.',
        );
    }

    public function testAnExpiredTokenIsRefused(): void
    {
        $token = $this->requestLink(self::MEMBER);

        $result = $this->auth->completeReset(
            $token,
            self::GOOD_PASSWORD,
            $this->now + PasswordAuthenticator::RESET_TTL_SECONDS + 1,
        );

        self::assertSame(PasswordResetResult::INVALID_TOKEN, $result->status);
    }

    public function testAnInventedTokenIsRefused(): void
    {
        $this->requestLink(self::MEMBER);

        self::assertSame(
            PasswordResetResult::INVALID_TOKEN,
            $this->auth->completeReset('a-token-nobody-issued', self::GOOD_PASSWORD, $this->now)->status,
        );
    }

    public function testAWeakPasswordIsRefusedButLeavesTheLinkUsable(): void
    {
        // The distinction that matters to whoever is holding the phone:
        // being told the password is too short must not also cost them
        // the link and force another email.
        $token = $this->requestLink(self::MEMBER);

        $rejected = $this->auth->completeReset($token, 'short', $this->now);

        self::assertSame(PasswordResetResult::WEAK_PASSWORD, $rejected->status);
        self::assertNotSame('', $rejected->message);

        self::assertTrue($this->auth->completeReset($token, self::GOOD_PASSWORD, $this->now)->isOk());
    }

    public function testSettingAPasswordClearsALockout(): void
    {
        // A member locked out by somebody guessing at their account must
        // be able to recover through the link rather than waiting it out.
        $this->givenPassword(self::MEMBER, self::GOOD_PASSWORD);

        for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
            $this->auth->attemptLogin(self::MEMBER, 'wrong', $this->now);
        }

        $token = $this->requestLink(self::MEMBER);
        $fresh = 'a completely different passphrase';

        self::assertTrue($this->auth->completeReset($token, $fresh, $this->now)->isOk());
        self::assertNotNull($this->auth->attemptLogin(self::MEMBER, $fresh, $this->now));
    }

    public function testTheStoredHashIsNotThePassword(): void
    {
        // Stated as a test because it is the whole point of the table.
        $token = $this->requestLink(self::MEMBER);
        $this->auth->completeReset($token, self::GOOD_PASSWORD, $this->now);

        $hash = $this->credentials->rows[self::MEMBER]->passwordHash;

        self::assertNotSame(self::GOOD_PASSWORD, $hash);
        self::assertStringNotContainsString(self::GOOD_PASSWORD, $hash);
        self::assertTrue(password_verify(self::GOOD_PASSWORD, $hash));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /**
     * Ask for a link, and read the raw token back out of the email.
     *
     * <b>Through the real mailer, on purpose.</b> The authenticator hands
     * the raw token to nothing else — the store keeps only its SHA-256 —
     * so the email is genuinely the only place it exists, exactly as it
     * is in production. Reaching in another way would prove less and
     * would stop noticing if the mail ever went out without the token in
     * it.
     */
    private function requestLink(string $email): string
    {
        $before = count(WpState::$mail);

        $this->auth->beginReset($email, $this->now);

        // Queued past the response in production; flushed by hand here,
        // since there is no shutdown to wait for.
        $this->mailer->flush();

        self::assertGreaterThan($before, count(WpState::$mail), 'No link was emailed.');

        $body = (string) (WpState::$mail[count(WpState::$mail) - 1]['message'] ?? '');

        self::assertSame(
            1,
            preg_match('~link://password\?token=([A-Za-z0-9_-]+)~', $body, $matches),
            'The email did not carry a usable link.',
        );

        return $matches[1];
    }

    private function givenPassword(string $email, string $password): void
    {
        $this->credentials->upsertPasswordHash(
            $email,
            (string) password_hash($password, PASSWORD_DEFAULT),
            $this->now,
        );
    }

    /**
     * A repository that knows one member.
     *
     * A stub rather than a hand-written double: MemberRepository has nine
     * methods and Member twenty-three, and implementing all of them to
     * answer one question would bury the one answer that matters.
     */
    private function members(): MemberRepository
    {
        $member = $this->createStub(Member::class);
        $member->method('getId')->willReturn(7);
        $member->method('getPersonalEmail')->willReturn(self::MEMBER);

        $repository = $this->createStub(MemberRepository::class);
        $repository->method('findByEmail')->willReturnCallback(
            fn(string $email): ?Member =>
                strtolower(trim($email)) === self::MEMBER ? $member : null
        );

        return $repository;
    }
}
