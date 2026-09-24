<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\PasswordResetResult;
use Fellowship\Devices\MemberGate;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
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

const PASSWORD_AUTHENTICATOR_MEMBER = 'member@example.org';

const PASSWORD_AUTHENTICATOR_STRANGER = 'nobody@example.org';

const PASSWORD_AUTHENTICATOR_GOOD_PASSWORD = 'correct horse battery staple';

beforeEach(function () {
    $this->now = 1_800_000_000;
    $this->credentials = new InMemoryPasswordCredentialRepository();

    $this->mailer = new PasswordResetMailer();

    $this->auth = new PasswordAuthenticator(
        $this->credentials,
        new MemberGate(passwordAuthenticatorMembers()),
        $this->mailer,
        new PasswordPolicy(),
    );
});

// ── Signing in ────────────────────────────────────────────────────

test('a correct password proves the address', function () {
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    $identity = $this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now);

    expect($identity)->not->toBeNull();
    expect($identity->email)->toBe(PASSWORD_AUTHENTICATOR_MEMBER);
    expect($identity->provider)->toBe('password');
});

test('the address is normalised before it is matched', function () {
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    expect($this->auth->attemptLogin('  Member@Example.ORG ', PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->not->toBeNull();
});

test('a wrong password is refused', function () {
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, 'not the password', $this->now))->toBeNull();
});

test('an address with no password is refused', function () {
    // The normal state of affairs: passwords are set only on request,
    // so most members never have one.
    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->toBeNull();
});

test('guessing at an unknown address creates no row', function () {
    // Otherwise the table becomes a list of every address anybody has
    // ever tried, and a lockout could be induced for an address that
    // has no account at all.
    $this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_STRANGER, 'anything', $this->now);

    expect($this->credentials->rows)->toBe([]);
});

// ── Lockout ───────────────────────────────────────────────────────

test('five wrong passwords lock the account', function () {
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
        expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, 'wrong', $this->now))->toBeNull();
    }

    // The telling assertion: the *right* password is now refused too.
    // A lockout that let the correct password through would stop
    // nothing, since that is what the attacker is searching for.
    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->toBeNull();
});

test('the lockout expires', function () {
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
        $this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, 'wrong', $this->now);
    }

    $later = $this->now + PasswordAuthenticator::LOCKOUT_SECONDS + 1;

    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $later))->not->toBeNull();
});

test('a successful login clears the failure count', function () {
    // Without this a member who mistypes four times over a month,
    // signing in successfully between each, is locked out by the
    // fifth — a counter that only ever climbs.
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS - 1; $i++) {
        $this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, 'wrong', $this->now);
    }

    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->not->toBeNull();
    expect($this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->failedAttempts)->toBe(0);
});

// ── Asking for a link ─────────────────────────────────────────────

test('a request for a member stores a hashed token', function () {
    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_MEMBER, $this->now);

    $row = $this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER] ?? null;
    expect($row)->not->toBeNull();
    expect($row->resetTokenHash)->not->toBe('');
    expect(strlen($row->resetTokenHash))->toBe(64, 'The stored token must be a SHA-256 hex digest.');
    expect($row->resetExpiresAt)->toBe($this->now + PasswordAuthenticator::RESET_TTL_SECONDS);
});

test('a request for a stranger does nothing at all', function () {
    // The endpoint answers identically either way, so this is what
    // stops the *database* becoming the thing that reveals who is a
    // member.
    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_STRANGER, $this->now);

    expect($this->credentials->rows)->toBe([]);
});

test('a second request inside the cooldown is ignored', function () {
    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_MEMBER, $this->now);
    $first = $this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->resetTokenHash;

    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_MEMBER, $this->now + 5);

    expect($this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->resetTokenHash)->toBe($first, 'A second request inside the cooldown must not mint a new token, or a nuisance actor can flood an inbox.');
});

test('a request after the cooldown issues a fresh token', function () {
    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_MEMBER, $this->now);
    $first = $this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->resetTokenHash;

    $this->auth->beginReset(PASSWORD_AUTHENTICATOR_MEMBER, $this->now + PasswordAuthenticator::RESET_COOLDOWN_SECONDS + 1);

    expect($this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->resetTokenHash)->not->toBe($first);
});

// ── Completing one ────────────────────────────────────────────────

test('a valid token sets the password', function () {
    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);

    $result = $this->auth->completeReset($token, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now);

    expect($result->isOk())->toBeTrue();
    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->not->toBeNull();
});

test('a token is single use', function () {
    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);

    expect($this->auth->completeReset($token, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now)->isOk())->toBeTrue();

    $second = $this->auth->completeReset($token, 'another perfectly fine passphrase', $this->now);

    expect($second->status)->toBe(PasswordResetResult::INVALID_TOKEN);
    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now))->not->toBeNull('The first password must still stand after the replay is refused.');
});

test('an expired token is refused', function () {
    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);

    $result = $this->auth->completeReset(
        $token,
        PASSWORD_AUTHENTICATOR_GOOD_PASSWORD,
        $this->now + PasswordAuthenticator::RESET_TTL_SECONDS + 1,
    );

    expect($result->status)->toBe(PasswordResetResult::INVALID_TOKEN);
});

test('an invented token is refused', function () {
    requestLink(PASSWORD_AUTHENTICATOR_MEMBER);

    expect($this->auth->completeReset('a-token-nobody-issued', PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now)->status)->toBe(PasswordResetResult::INVALID_TOKEN);
});

test('a weak password is refused but leaves the link usable', function () {
    // The distinction that matters to whoever is holding the phone:
    // being told the password is too short must not also cost them
    // the link and force another email.
    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);

    $rejected = $this->auth->completeReset($token, 'short', $this->now);

    expect($rejected->status)->toBe(PasswordResetResult::WEAK_PASSWORD);
    expect($rejected->message)->not->toBe('');

    expect($this->auth->completeReset($token, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now)->isOk())->toBeTrue();
});

test('setting a password clears a lockout', function () {
    // A member locked out by somebody guessing at their account must
    // be able to recover through the link rather than waiting it out.
    passwordAuthenticatorGivenPassword(PASSWORD_AUTHENTICATOR_MEMBER, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);

    for ($i = 0; $i < PasswordAuthenticator::MAX_FAILED_ATTEMPTS; $i++) {
        $this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, 'wrong', $this->now);
    }

    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);
    $fresh = 'a completely different passphrase';

    expect($this->auth->completeReset($token, $fresh, $this->now)->isOk())->toBeTrue();
    expect($this->auth->attemptLogin(PASSWORD_AUTHENTICATOR_MEMBER, $fresh, $this->now))->not->toBeNull();
});

test('the stored hash is not the password', function () {
    // Stated as a test because it is the whole point of the table.
    $token = requestLink(PASSWORD_AUTHENTICATOR_MEMBER);
    $this->auth->completeReset($token, PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $this->now);

    $hash = $this->credentials->rows[PASSWORD_AUTHENTICATOR_MEMBER]->passwordHash;

    expect($hash)->not->toBe(PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);
    expect($hash)->not->toContain(PASSWORD_AUTHENTICATOR_GOOD_PASSWORD);
    expect(password_verify(PASSWORD_AUTHENTICATOR_GOOD_PASSWORD, $hash))->toBeTrue();
});

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
function requestLink(string $email): string
{
    $before = count(WpState::$mail);

    test()->auth->beginReset($email, test()->now);

    // Queued past the response in production; flushed by hand here,
    // since there is no shutdown to wait for.
    test()->mailer->flush();

    expect(count(WpState::$mail))->toBeGreaterThan($before, 'No link was emailed.');

    $body = (string) (WpState::$mail[count(WpState::$mail) - 1]['message'] ?? '');

    // The code is on a line of its own, base64url of 32 random bytes.
    expect(preg_match('~^([A-Za-z0-9_-]{40,})$~m', $body, $matches))->toBe(1, 'The email did not carry a usable code.');

    return $matches[1];
}

function passwordAuthenticatorGivenPassword(string $email, string $password): void
{
    test()->credentials->upsertPasswordHash(
        $email,
        (string) password_hash($password, PASSWORD_DEFAULT),
        test()->now,
    );
}

/**
 * A repository that knows one member.
 *
 * A stub rather than a hand-written double: MemberRepository has nine
 * methods and Member twenty-three, and implementing all of them to
 * answer one question would bury the one answer that matters.
 */
function passwordAuthenticatorMembers(): MemberRepository
{
    $member = test()->createStub(Member::class);
    $member->method('getId')->willReturn(7);
    $member->method('getPersonalEmail')->willReturn(PASSWORD_AUTHENTICATOR_MEMBER);

    $repository = test()->createStub(MemberRepository::class);
    $repository->method('findByEmail')->willReturnCallback(
        fn(string $email): ?Member =>
            strtolower(trim($email)) === PASSWORD_AUTHENTICATOR_MEMBER ? $member : null
    );

    return $repository;
}
