<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Guardian\Jwt\JwtVerifier;

/**
 * Decides whether a request comes from this project's Cloud Functions.
 *
 * Link's Functions keep no member data, so they ask Fellowship who somebody
 * is and who a message reaches. They prove themselves with a Google-signed
 * OIDC token, and {@see JwtVerifier} does the signature, expiry, issuer and
 * audience checks. What this adds is two pins:
 *
 * - <b>The audience is this site's own service address.</b> A token Google
 *   signed for anything else, however genuine, is refused here.
 * - <b>The email is the service account Fellowship already holds.</b> Every
 *   Google account can get a Google-signed token, so a valid signature alone
 *   proves nothing. The Functions run as that same account, which is why this
 *   is not a second setting to get wrong.
 *
 * The caller must ask for the email claim, which on Google's metadata server
 * means `format=full`. A token without one is refused.
 */
final class ServiceCaller
{
    public const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

    public const ISSUER = 'https://accounts.google.com';

    /** @var Closure(): string */
    private readonly Closure $expectedEmail;

    /** @var Closure(): string */
    private readonly Closure $expectedAudience;

    /**
     * @param callable(): string $expectedEmail    The service account's address,
     *                                             or '' when none is configured.
     * @param callable(): string $expectedAudience What the token must be for.
     */
    public function __construct(
        private readonly JwtVerifier $verifier,
        callable $expectedEmail,
        callable $expectedAudience,
    ) {
        $this->expectedEmail = Closure::fromCallable($expectedEmail);
        $this->expectedAudience = Closure::fromCallable($expectedAudience);
    }

    public function isConfigured(): bool
    {
        return ($this->expectedEmail)() !== '';
    }

    public function accepts(string $authorizationHeader): bool
    {
        $expectedEmail = strtolower(($this->expectedEmail)());
        if ($expectedEmail === '') {
            return false;
        }

        if (!preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $authorizationHeader, $matches)) {
            return false;
        }

        $claims = $this->verifier->verify(
            $matches[1],
            self::JWKS_URL,
            self::ISSUER,
            ($this->expectedAudience)(),
        );
        if ($claims === null) {
            return false;
        }

        $email = $claims['email'] ?? null;

        return is_string($email)
            && strtolower($email) === $expectedEmail
            && ($claims['email_verified'] ?? null) === true;
    }
}
