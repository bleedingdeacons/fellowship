<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Logger\HasLogger;

/**
 * Verifies an OIDC ID token against a provider's published JWKS.
 *
 * A port of Reach's verifier, kept line-for-line where it matters. This
 * is the code that decides whether a stranger's assertion about their
 * own email address is true, and the cost of a subtle difference between
 * two copies of it is that one of them is wrong and nobody knows which.
 *
 * The refusals worth naming:
 *
 * - <b>RS256 only.</b> `alg: none` is the textbook JWT forgery and an
 *   HMAC algorithm would let a token be signed with the public key
 *   anyone can fetch.
 * - <b>`exp` and `iat` are mandatory.</b> OIDC requires them. A token
 *   without `exp` would verify forever, and one without `iat` cannot be
 *   skew-checked against the future.
 * - <b>Issuer, audience and nonce are all checked.</b> Audience is what
 *   stops a token minted for somebody else's app being replayed at ours;
 *   nonce is what stops one minted for ours being replayed twice.
 *
 * Failures return null rather than throwing, and are logged without the
 * token: a caller has nothing useful to do with the distinction, and
 * saying which check failed helps only whoever is probing.
 */
final class JwtVerifier
{
    use HasLogger;
    use Base64Url;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    private const JWKS_CACHE_PREFIX = 'fellowship_jwks_';
    private const JWKS_CACHE_TTL = HOUR_IN_SECONDS;
    private const HTTP_TIMEOUT = 5;

    /** Tolerance for clock drift between this server and the provider. */
    private const CLOCK_SKEW_SECONDS = 60;

    /**
     * @return array<string, mixed>|null The verified claims, or null.
     */
    public function verify(
        string $jwt,
        string $jwksUrl,
        string $expectedIssuer,
        string $expectedAudience,
        ?string $expectedNonce = null
    ): ?array {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        [$header64, $payload64, $signature64] = $parts;

        $header = json_decode($this->base64UrlDecode($header64), true);
        $payload = json_decode($this->base64UrlDecode($payload64), true);
        if (!is_array($header) || !is_array($payload)) {
            return null;
        }

        // Algorithm must be RS256 — never trust 'none' or HMAC.
        if (($header['alg'] ?? null) !== 'RS256') {
            self::logWarning('JWT: rejected algorithm', ['alg' => $header['alg'] ?? null]);
            return null;
        }

        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            return null;
        }

        $jwk = $this->findKey($jwksUrl, $kid);
        if ($jwk === null) {
            // Cache miss for a freshly rotated key — refetch once with the
            // cache busted before giving up, or every sign-in fails for an
            // hour after a provider rotates.
            $jwk = $this->findKey($jwksUrl, $kid, forceRefresh: true);
            if ($jwk === null) {
                self::logWarning('JWT: no matching key', ['kid' => $kid, 'jwks' => $jwksUrl]);
                return null;
            }
        }

        $publicKey = $this->jwkToPem($jwk);
        if ($publicKey === null) {
            return null;
        }

        $signature = $this->base64UrlDecode($signature64);
        $signed = $header64 . '.' . $payload64;
        if (openssl_verify($signed, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            self::logWarning('JWT: signature verification failed');
            return null;
        }

        $now = time();

        if (!isset($payload['exp']) || !is_numeric($payload['exp'])) {
            self::logWarning('JWT: missing or non-numeric exp claim');
            return null;
        }
        if (!isset($payload['iat']) || !is_numeric($payload['iat'])) {
            self::logWarning('JWT: missing or non-numeric iat claim');
            return null;
        }
        if ($now > ((int) $payload['exp'] + self::CLOCK_SKEW_SECONDS)) {
            return null;
        }
        if (((int) $payload['iat'] - self::CLOCK_SKEW_SECONDS) > $now) {
            return null;
        }
        if (($payload['iss'] ?? null) !== $expectedIssuer) {
            return null;
        }

        // aud may be a string or an array of strings.
        $aud = $payload['aud'] ?? null;
        $audMatches = is_string($aud)
            ? $aud === $expectedAudience
            : (is_array($aud) && in_array($expectedAudience, $aud, true));
        if (!$audMatches) {
            return null;
        }

        if ($expectedNonce !== null && ($payload['nonce'] ?? null) !== $expectedNonce) {
            return null;
        }

        return $payload;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findKey(string $jwksUrl, string $kid, bool $forceRefresh = false): ?array
    {
        $cacheKey = self::JWKS_CACHE_PREFIX . md5($jwksUrl);
        if ($forceRefresh) {
            delete_transient($cacheKey);
        }

        $jwks = get_transient($cacheKey);
        if (!is_array($jwks)) {
            $jwks = $this->fetchJwks($jwksUrl);
            if ($jwks === null) {
                return null;
            }
            set_transient($cacheKey, $jwks, self::JWKS_CACHE_TTL);
        }

        $keys = $jwks['keys'] ?? [];
        if (!is_array($keys)) {
            return null;
        }

        foreach ($keys as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchJwks(string $url): ?array
    {
        $response = wp_remote_get($url, [
            'timeout' => self::HTTP_TIMEOUT,
            'headers' => ['Accept' => 'application/json'],
        ]);

        if (is_wp_error($response)) {
            self::logWarning('JWKS fetch error', ['url' => $url, 'error' => $response->get_error_message()]);
            return null;
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code < 200 || $code >= 300) {
            return null;
        }

        $decoded = json_decode((string) wp_remote_retrieve_body($response), true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Build a PEM public key from an RSA JWK.
     *
     * Hand-rolled DER because PHP has no JWK reader and pulling a JOSE
     * library in for one key type would be a dependency for thirty lines.
     *
     * @param array<string, mixed> $jwk
     */
    private function jwkToPem(array $jwk): ?string
    {
        if (($jwk['kty'] ?? null) !== 'RSA') {
            return null;
        }

        $n = $this->base64UrlDecode((string) ($jwk['n'] ?? ''));
        $e = $this->base64UrlDecode((string) ($jwk['e'] ?? ''));
        if ($n === '' || $e === '') {
            return null;
        }

        $rsaPublicKey = $this->derSequence($this->derInteger($n) . $this->derInteger($e));
        // OID for rsaEncryption + NULL parameters.
        $algorithmIdentifier = $this->derSequence(
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00"
        );
        $spki = $this->derSequence($algorithmIdentifier . $this->derBitString($rsaPublicKey));

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private function derInteger(string $bytes): string
    {
        // RSA integers are unsigned; prefix a 0x00 byte if the high bit is
        // set so the DER INTEGER is not read as negative.
        if ($bytes !== '' && (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . $this->derLength(strlen($bytes)) . $bytes;
    }

    private function derSequence(string $contents): string
    {
        return "\x30" . $this->derLength(strlen($contents)) . $contents;
    }

    private function derBitString(string $contents): string
    {
        // Leading byte is the count of unused bits in the final byte,
        // always 0 here.
        $contents = "\x00" . $contents;
        return "\x03" . $this->derLength(strlen($contents)) . $contents;
    }

    private function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
