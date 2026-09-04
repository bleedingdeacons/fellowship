<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Password strength policy, following modern guidance rather than the old
 * "must contain uppercase, lowercase, number and symbol" composition rules.
 *
 * The relevant guidance is NIST SP 800-63B (§5.1.1.2) and the UK NCSC
 * password guidance, which converge on:
 *
 *   - A sensible *minimum* length (NIST floor: 8) and a generous *maximum*
 *     (NIST: accept at least 64) — length beats composition. Longer
 *     pass-phrases of a few random words are encouraged.
 *   - NO composition rules and NO periodic forced rotation.
 *   - Accept all printable characters, spaces and Unicode; never truncate.
 *     Length is measured in Unicode code points.
 *   - Reject passwords that are known to be weak: common/breached passwords
 *     and context-specific values (here, the member's email and the site
 *     name), which an attacker guesses first.
 *
 * The check is deliberately offline: a compact deny-list of the most common
 * passwords plus context terms. It is the single source of truth for what
 * Fellowship considers an acceptable secret; {@see PasswordAuthenticator} calls
 * it when a member sets or resets a password.
 *
 * <b>Ported from Reach deliberately unchanged.</b> The two plugins gate
 * the same people on the same intergroup, and a member who satisfies one
 * password rule and fails the other would be told, correctly and
 * uselessly, that the same secret is both acceptable and not. If the
 * minimum length moves here it should move there.
 */
final class PasswordPolicy
{
    /**
     * Minimum length. Set above the NIST SP 800-63B floor of 8: a longer
     * minimum (in the spirit of NCSC's "favour length" guidance) resists
     * guessing far better, and at this length a memorable pass-phrase of a
     * few words is the natural way to comply.
     */
    public const MIN_LENGTH = 14;

    /**
     * Upper bound. Comfortably exceeds NIST's "accept at least 64" while
     * capping the work an Argon2id hash does on a single input (a defence
     * against a long-password denial-of-service).
     */
    public const MAX_LENGTH = 128;

    /**
     * The most common passwords, which attackers try first. Lower-cased;
     * compared for equality after the candidate is normalised. This is a
     * pragmatic offline deny-list, not an exhaustive breach corpus — a
     * production deployment can layer a Pwned-Passwords range lookup on top
     * without changing this contract.
     *
     * With a 14-character minimum, short weak passwords are already rejected
     * on length; the entries that actually earn their keep here are the
     * *long-but-predictable* ones (repeated words, keyboard walks, padded
     * numbers). Both are kept so the list stays correct if the minimum ever
     * changes.
     *
     * @var string[]
     */
    private const COMMON = [
        // Long but predictable (>= 14 chars) — the ones the length check
        // does NOT already catch.
        'passwordpassword', 'password123456', 'passwordpassword1', '123456789012345',
        '12345678901234', '1234567890123', 'qwertyuiopasdfgh', 'qwertyuiopasdf',
        'iloveyou123456', 'letmeinletmein', 'welcomewelcome1', 'aaaaaaaaaaaaaa',
        'q1w2e3r4t5y6u7', 'zaq1zaq1zaq1zaq1', 'adminadminadmin', 'trustno1trustno1',
        // Classic short common passwords — caught on length today, kept for
        // completeness and in case the minimum is ever lowered.
        'password', 'password1', 'password12', 'password123', 'passw0rd', 'p@ssw0rd',
        '12345678', '123456789', '1234567890', '87654321', '11111111', '00000000',
        'qwertyui', 'qwertyuiop', 'qwerty123', 'asdfghjkl', '1q2w3e4r', '1qaz2wsx',
        'letmein', 'letmein1', 'welcome1', 'welcome123', 'iloveyou', 'iloveyou1',
        'trustno1', 'sunshine', 'princess', 'football', 'baseball', 'superman',
        'dragon123', 'monkey123', 'whatever', 'changeme', 'admin123', 'administrator',
        'test1234', 'abc12345', 'abcd1234', 'secret12', 'master123', 'shadow123',
        'computer1', 'internet1', 'password!', 'passw0rd!', 'qwerty12',
    ];

    /**
     * Validate a candidate password for the given context.
     *
     * @param array{email?: string} $context Context-specific terms to reject,
     *        principally the member's email (its local-part is the "username").
     * @return string|null A user-facing reason it was rejected, or null if OK.
     */
    public function validate(string $password, array $context = []): ?string
    {
        // Measure in code points, not bytes, so a Unicode pass-phrase isn't
        // wrongly rejected/accepted on its byte length.
        $length = function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen($password);

        if ($length < self::MIN_LENGTH) {
            return sprintf('Please use at least %d characters. A few random words make a strong, memorable password.', self::MIN_LENGTH);
        }
        if ($length > self::MAX_LENGTH) {
            return sprintf('Please use no more than %d characters.', self::MAX_LENGTH);
        }

        $normalised = strtolower(trim($password));

        if (in_array($normalised, self::COMMON, true)) {
            return 'That password is too common and easily guessed. Please choose a less predictable one.';
        }

        if ($this->matchesContext($normalised, $context)) {
            return 'Please don’t base your password on your email address or the site name.';
        }

        return null;
    }

    /**
     * Convenience boolean form of {@see validate()}.
     *
     * @param array{email?: string} $context
     */
    public function isAcceptable(string $password, array $context = []): bool
    {
        return $this->validate($password, $context) === null;
    }

    /**
     * Whether the password is built around a context-specific term an
     * attacker would try early: the member's email (or its local-part) or
     * the site name. Terms shorter than 4 characters are ignored to avoid
     * rejecting passwords that merely happen to contain a short fragment.
     *
     * @param array{email?: string} $context
     */
    private function matchesContext(string $normalised, array $context): bool
    {
        $terms = [];

        $email = isset($context['email']) ? strtolower(trim((string) $context['email'])) : '';
        if ($email !== '') {
            $terms[] = $email;
            $at = strpos($email, '@');
            $local = $at === false ? $email : substr($email, 0, $at);
            if (strlen($local) >= 4) {
                $terms[] = $local;
            }
        }

        $site = strtolower(trim((string) get_bloginfo('name')));
        if (strlen($site) >= 4) {
            $terms[] = $site;
        }

        foreach ($terms as $term) {
            // Every term is non-empty by construction above.
            if (str_contains($normalised, $term)) {
                return true;
            }
        }
        return false;
    }
}
