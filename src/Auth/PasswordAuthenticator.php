<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Devices\MemberGate;

/**
 * Email + password authentication, plus the emailed set/reset flow.
 *
 * This is the second sign-in path alongside OAuth. It deliberately proves
 * only "this caller knows the password for this email" — exactly as an
 * OAuth provider proves "this caller controls this email" — and returns a
 * {@see VerifiedIdentity}. Whether that identity is *allowed* into Fellowship
 * (the 12th-stepper / telephone-responder gate) is decided by the REST
 * controller, keeping this class free of HTTP and authorisation concerns.
 *
 * Security posture:
 *   - Passwords are hashed with Argon2id ({@see password_hash()} with
 *     {@see PASSWORD_ARGON2ID}, OWASP baseline parameters), falling back to
 *     the platform default only where Argon2id isn't compiled in. Hashes are
 *     rehashed transparently on login when the algorithm/parameters move on.
 *   - The chosen password must satisfy {@see PasswordPolicy} (length-based,
 *     NIST SP 800-63B / NCSC style, no composition rules, common/context
 *     passwords rejected).
 *   - A wrong password and an email with no password behave identically,
 *     including running a throwaway {@see password_verify()} so the two
 *     can't be told apart by response timing (no account enumeration).
 *   - Per-account lockout after {@see MAX_FAILED_ATTEMPTS} failures.
 *   - Reset tokens are random 32-byte values mailed in the clear but
 *     stored only as a SHA-256 hash, single-use and 60-minute expiry.
 *   - A reset link is issued only for an eligible member; a request for
 *     any other address is a silent no-op so the caller can respond
 *     identically either way.
 *
 * A member's credential is GDPR-protected personal data: sign-ins and
 * password changes are audit-logged by the REST controller, and the stored
 * row is purged when the member is deleted (see Plugin bootstrap).
 */
final class PasswordAuthenticator
{
    use Base64Url;

    /** Session/identity provider label for password sign-ins. */
    public const PROVIDER = 'password';

    /** Consecutive failures before the account is locked. */
    public const MAX_FAILED_ATTEMPTS = 5;

    /** How long a locked account stays locked. */
    public const LOCKOUT_SECONDS = 15 * 60;

    /** How long an emailed reset link stays valid. */
    public const RESET_TTL_SECONDS = 60 * 60;

    /**
     * Minimum spacing between reset emails to the same address. A second
     * request inside this window is a silent no-op, so a nuisance actor
     * can't repeatedly flood a member's inbox with reset links.
     */
    public const RESET_COOLDOWN_SECONDS = 90;

    public function __construct(
        private readonly PasswordCredentialRepository $credentials,
        private readonly MemberGate $gate,
        private readonly PasswordResetMailer $mailer,
        private readonly PasswordPolicy $policy,
    ) {
    }

    /**
     * Verify an email + password. Returns a proven identity on success, or
     * null for any failure (unknown email, no password set, wrong password,
     * or a locked account) — the caller must not distinguish these.
     */
    public function attemptLogin(string $email, string $password, int $now): ?VerifiedIdentity
    {
        $email = $this->normaliseEmail($email);
        if ($email === '') {
            $this->burnTime($password);
            return null;
        }

        $cred = $this->credentials->find($email);
        if ($cred === null || !$cred->hasPassword()) {
            // Equalise timing with the real verify path below.
            $this->burnTime($password);
            return null;
        }

        if ($cred->isLocked($now)) {
            // Burn the same time as a real verify so a locked account can't
            // be told apart from a wrong password by response timing.
            $this->burnTime($password);
            return null;
        }

        if (!password_verify($password, $cred->passwordHash)) {
            $this->registerFailure($cred, $now);
            return null;
        }

        // Correct password. Rehash if the algorithm/parameters have moved on
        // (e.g. an old bcrypt hash from before Argon2id, or upgraded Argon2id
        // cost). upsert also clears the failed-attempt counters; otherwise
        // just clear the counters.
        if (password_needs_rehash($cred->passwordHash, self::algorithm(), self::hashOptions())) {
            $this->credentials->upsertPasswordHash($email, $this->hashPassword($password), $now);
        } else {
            $this->credentials->resetFailedAttempts($email, $now);
        }

        return new VerifiedIdentity(
            email: $email,
            provider: self::PROVIDER,
            sub: $email,
        );
    }

    /**
     * Begin a set/reset: mint a one-time token, store its hash, and mail
     * the link — but only when $email belongs to an eligible member. For
     * any other address this is a silent no-op, so the REST layer can
     * always answer "if that address is registered, we've emailed a link"
     * without revealing whether it was.
     */
    public function beginReset(string $email, int $now): void
    {
        $email = $this->normaliseEmail($email);
        if ($email === '') {
            return;
        }

        if (!$this->isEligibleMember($email)) {
            return;
        }

        // Anti-flood: if a reset link was issued for this address within the
        // cooldown window, don't send another. Still silent — the endpoint's
        // response is identical whether or not a link was actually sent, so
        // this leaks nothing about the account.
        $existing = $this->credentials->find($email);
        if ($existing !== null && $existing->resetTokenHash !== '') {
            $issuedAt = $existing->resetExpiresAt - self::RESET_TTL_SECONDS;
            if ($issuedAt > $now - self::RESET_COOLDOWN_SECONDS) {
                return;
            }
        }

        $rawToken  = $this->base64UrlEncode(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);

        $this->credentials->storeResetToken($email, $tokenHash, $now + self::RESET_TTL_SECONDS, $now);
        // Queued, not sent: the send happens after the response so that
        // an eligible address and an ineligible one take the same time
        // to answer. See PasswordResetMailer for the full reasoning.
        $this->mailer->queue($email, $rawToken);
    }

    /**
     * Complete a set/reset from the emailed link.
     *
     * Validates the one-time token first (a bad/expired/spent token is the
     * blocking error), then the chosen password against {@see PasswordPolicy}
     * using the credential's email as context. Only on success is the token
     * consumed and the new hash written — so a policy rejection leaves the
     * link usable for another try.
     */
    public function completeReset(string $rawToken, string $newPassword, int $now): PasswordResetResult
    {
        $rawToken = trim($rawToken);
        if ($rawToken === '') {
            return PasswordResetResult::invalidToken();
        }

        $tokenHash = hash('sha256', $rawToken);
        $cred = $this->credentials->findByResetTokenHash($tokenHash);
        if (
            $cred === null
            || !$cred->hasValidResetToken($now)
            || !hash_equals($cred->resetTokenHash, $tokenHash)
        ) {
            return PasswordResetResult::invalidToken();
        }

        $reason = $this->policy->validate($newPassword, ['email' => $cred->email]);
        if ($reason !== null) {
            return PasswordResetResult::weakPassword($reason);
        }

        // upsert sets the new hash and clears the (now spent) token and any
        // lockout, so the link is single-use.
        $this->credentials->upsertPasswordHash(
            $cred->email,
            $this->hashPassword($newPassword),
            $now,
        );

        return PasswordResetResult::ok($cred->email);
    }

    private function registerFailure(PasswordCredential $cred, int $now): void
    {
        $attempts    = $cred->failedAttempts + 1;
        $lockedUntil = 0;

        // On hitting the threshold, lock and reset the counter so the next
        // window starts fresh after the lockout expires.
        if ($attempts >= self::MAX_FAILED_ATTEMPTS) {
            $lockedUntil = $now + self::LOCKOUT_SECONDS;
            $attempts    = 0;
        }

        $this->credentials->recordFailedAttempt($cred->email, $attempts, $lockedUntil, $now);
    }

    /**
     * Whether the member behind this email may use Fellowship.
     *
     * <b>The same gate the OAuth paths use, deliberately.</b> A password
     * is a way of proving an address, exactly as an ID token is; it is not
     * a second answer to who is allowed in. Asking a different question
     * here is how a member ends up able to sign in one way and not the
     * other, with nothing in either code path to explain it.
     */
    private function isEligibleMember(string $email): bool
    {
        return $this->gate->authorisedMember($email) !== null;
    }

    private function normaliseEmail(string $email): string
    {
        $email = strtolower(trim($email));
        return is_email($email) ? $email : '';
    }

    /**
     * Run a throwaway verify so the no-credential path costs the same as a
     * real one. The dummy hash uses the same algorithm as real credentials
     * so the timing genuinely matches. Computed once per request.
     */
    private function burnTime(string $password): void
    {
        static $dummy = null;
        if ($dummy === null) {
            $dummy = $this->hashPassword('fellowship-timing-equaliser');
        }
        password_verify($password, $dummy);
    }

    /** Hash a password with the configured algorithm + parameters. */
    private function hashPassword(string $password): string
    {
        return password_hash($password, self::algorithm(), self::hashOptions());
    }

    /**
     * Argon2id where the platform provides it (the modern recommendation),
     * otherwise the platform default (bcrypt). Chosen at runtime so the code
     * still works on a PHP built without Argon2 support.
     */
    private static function algorithm(): string
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    }

    /**
     * OWASP baseline Argon2id parameters (19 MiB memory, 2 iterations, 1
     * lane). Empty for the bcrypt fallback, which takes no such options.
     *
     * @return array<string, int>
     */
    private static function hashOptions(): array
    {
        if (self::algorithm() === PASSWORD_DEFAULT) {
            return [];
        }
        return [
            'memory_cost' => 19456,
            'time_cost'   => 2,
            'threads'     => 1,
        ];
    }
}
