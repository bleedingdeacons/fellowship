<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;
use PHPUnit\Framework\TestCase;

/**
 * The code that decides whether a stranger's claim about their own email
 * address is true.
 *
 * <b>Untested until now, which is the wrong shape of gap.</b> Everything
 * downstream of this class — the member gate, the device row, every
 * message ever sealed to the handset — rests on it refusing a token it
 * should refuse. A verifier that accepted `alg: none` would hand an
 * enrolment to anybody who could type an email address, and nothing else
 * in the plugin would notice.
 *
 * So the tests forge. Each one mints a real RS256 token with a real
 * keypair, serves a real JWKS through the fake HTTP transport, and then
 * breaks exactly one thing. The positive case exists to prove the
 * negatives are failing for the reason claimed rather than because the
 * fixture never worked.
 *
 * Keypairs are generated per test rather than committed — a fixture here
 * would mean a private key in a public repository.
 */
final class JwtVerifierTest extends TestCase
{
    private const ISSUER = 'https://appleid.apple.com';
    private const JWKS_URL = 'https://appleid.apple.com/auth/keys';
    private const AUDIENCE = 'org.aa-bristol.link';
    private const KID = 'test-key-1';

    /** @var resource|\OpenSSLAsymmetricKey */
    private $key;

    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();
        WpState::reset();

        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            // The OPENSSL_CONF trap: without a usable openssl.cnf every
            // assertion below would be about the environment rather than
            // the verifier. Said plainly, because a silent skip here would
            // report a green suite that tested nothing.
            self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $this->key = $key;
    }

    public function testAWellFormedTokenVerifies(): void
    {
        $this->serveJwks();

        $claims = $this->verify($this->token());

        self::assertIsArray($claims);
        self::assertSame('member@example.org', $claims['email']);
        self::assertSame('000123.abc.456', $claims['sub']);
    }

    public function testAnUnsignedTokenIsRejected(): void
    {
        // The textbook forgery: claim no algorithm and hope the verifier
        // takes the payload's word for itself.
        $this->serveJwks();

        $header = $this->encode(['alg' => 'none', 'kid' => self::KID, 'typ' => 'JWT']);
        $payload = $this->encode($this->claims());

        self::assertNull($this->verify($header . '.' . $payload . '.'));
    }

    public function testAnHmacSignedTokenIsRejected(): void
    {
        // The subtler forgery: HS256 signed with the public key, which is
        // published and therefore known to everybody. A verifier that
        // dispatched on the header's alg would accept it.
        $this->serveJwks();

        $header = $this->encode(['alg' => 'HS256', 'kid' => self::KID, 'typ' => 'JWT']);
        $payload = $this->encode($this->claims());
        $signature = $this->base64Url(
            hash_hmac('sha256', $header . '.' . $payload, $this->publicKeyPem(), true)
        );

        self::assertNull($this->verify($header . '.' . $payload . '.' . $signature));
    }

    public function testATokenSignedByTheWrongKeyIsRejected(): void
    {
        $this->serveJwks();

        $other = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($other);

        self::assertNull($this->verify($this->token(signWith: $other)));
    }

    public function testATokenForAnotherAudienceIsRejected(): void
    {
        // What stops a token minted for somebody else's app being replayed
        // at this one.
        $this->serveJwks();

        self::assertNull($this->verify($this->token(['aud' => 'com.example.someone-else'])));
    }

    public function testATokenFromAnotherIssuerIsRejected(): void
    {
        $this->serveJwks();

        self::assertNull($this->verify($this->token(['iss' => 'https://accounts.google.com'])));
    }

    public function testAReplayedNonceIsRejected(): void
    {
        // What stops a token minted for this app being used twice.
        $this->serveJwks();

        self::assertNull($this->verify($this->token(['nonce' => 'a-different-nonce'])));
    }

    public function testAnExpiredTokenIsRejected(): void
    {
        $this->serveJwks();

        // Well past the 60-second skew allowance.
        self::assertNull($this->verify($this->token(['exp' => time() - 3600])));
    }

    public function testATokenIssuedInTheFutureIsRejected(): void
    {
        $this->serveJwks();

        self::assertNull($this->verify($this->token(['iat' => time() + 3600])));
    }

    public function testATokenWithNoExpiryIsRejected(): void
    {
        // Would otherwise verify forever.
        $this->serveJwks();

        self::assertNull($this->verify($this->token(remove: ['exp'])));
    }

    public function testATokenWithNoIssuedAtIsRejected(): void
    {
        $this->serveJwks();

        self::assertNull($this->verify($this->token(remove: ['iat'])));
    }

    public function testAnUnknownKeyIdIsRetriedOnceThenRejected(): void
    {
        // A provider that has just rotated leaves the cached JWKS without
        // the new kid. The verifier busts the cache and refetches once
        // rather than failing every sign-in for the cache's whole hour --
        // so two fetches, then a refusal.
        $this->serveJwks();
        $this->serveJwks();

        $header = $this->encode(['alg' => 'RS256', 'kid' => 'a-kid-nobody-published', 'typ' => 'JWT']);
        $payload = $this->encode($this->claims());
        $signature = $this->sign($header . '.' . $payload, $this->key);

        self::assertNull($this->verify($header . '.' . $payload . '.' . $signature));
        self::assertSame(2, FakeWpHttp::callCount());
    }

    public function testAFreshlyRotatedKeyIsFoundOnTheSecondFetch(): void
    {
        // The other half of the same behaviour, and the reason it exists:
        // the retry has to actually succeed when the key really is new.
        // Cached JWKS first, holding a kid this token was not signed with;
        // the refetch then carries the right one.
        WpState::$transients['fellowship_jwks_' . md5(self::JWKS_URL)] = [
            'keys' => [$this->jwk('a-stale-kid')],
        ];

        $this->serveJwks();

        $claims = $this->verify($this->token());

        self::assertIsArray($claims);
        self::assertSame(1, FakeWpHttp::callCount());
    }

    public function testAMalformedTokenIsRejected(): void
    {
        self::assertNull($this->verify('not-a-jwt'));
        self::assertNull($this->verify('only.two'));
        self::assertSame(0, FakeWpHttp::callCount(), 'A malformed token must not cost a JWKS fetch.');
    }

    public function testAJwksThatCannotBeFetchedIsRejected(): void
    {
        FakeWpHttp::pushResponse(500, 'upstream is having a day');

        self::assertNull($this->verify($this->token()));
    }

    /**
     * @param array<string, mixed> $overrides
     * @param list<string>         $remove
     * @param resource|\OpenSSLAsymmetricKey|null $signWith
     */
    private function token(array $overrides = [], array $remove = [], $signWith = null): string
    {
        $claims = array_merge($this->claims(), $overrides);

        foreach ($remove as $claim) {
            unset($claims[$claim]);
        }

        $header = $this->encode(['alg' => 'RS256', 'kid' => self::KID, 'typ' => 'JWT']);
        $payload = $this->encode($claims);

        return $header . '.' . $payload . '.' . $this->sign($header . '.' . $payload, $signWith ?? $this->key);
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(): array
    {
        return [
            'iss'            => self::ISSUER,
            'aud'            => self::AUDIENCE,
            'sub'            => '000123.abc.456',
            'email'          => 'member@example.org',
            'email_verified' => 'true',
            'nonce'          => 'the-issued-nonce',
            'iat'            => time(),
            'exp'            => time() + 600,
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function verify(string $jwt): ?array
    {
        return (new JwtVerifier())->verify(
            $jwt,
            self::JWKS_URL,
            self::ISSUER,
            self::AUDIENCE,
            'the-issued-nonce',
        );
    }

    private function serveJwks(): void
    {
        FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [$this->jwk(self::KID)]]));
    }

    /**
     * The public half, as a JWK.
     *
     * @return array<string, string>
     */
    private function jwk(string $kid): array
    {
        $details = openssl_pkey_get_details($this->key);
        self::assertIsArray($details);

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => $this->base64Url($details['rsa']['n']),
            'e'   => $this->base64Url($details['rsa']['e']),
        ];
    }

    private function publicKeyPem(): string
    {
        $details = openssl_pkey_get_details($this->key);
        self::assertIsArray($details);

        return (string) $details['key'];
    }

    /**
     * @param resource|\OpenSSLAsymmetricKey $key
     */
    private function sign(string $input, $key): string
    {
        $signature = '';
        openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);

        return $this->base64Url($signature);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function encode(array $data): string
    {
        return $this->base64Url((string) json_encode($data));
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
