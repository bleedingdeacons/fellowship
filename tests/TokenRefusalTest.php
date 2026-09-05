<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\TestCase;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Core\Settings;
use WP_Error;

/**
 * Every way an identity token is refused.
 *
 * <b>A verifier is only as good as its refusals.</b> The happy path is
 * one branch and the rest of the method is the security: an unsigned
 * token, a token signed with a key nobody published, a token for another
 * application, a token whose nonce belongs to a different sign-in. Each
 * of those is somebody's attempt, and each has to answer null rather
 * than throwing — a throw here becomes a 500 on the callback leg, which
 * tells the caller their guess was interesting.
 *
 * <b>Facebook is the one provider that requires PKCE.</b> Its callback
 * refuses a missing verifier with null rather than the exception the
 * authorise leg throws, because by that point the state has been
 * consumed and a browser is waiting — the only thing that can be done
 * with it is a redirect carrying an error.
 *
 * @covers \Fellowship\Auth\JwtVerifier
 * @covers \Fellowship\Auth\Providers\FacebookProvider
 */
final class TokenRefusalTest extends TestCase
{
    private const JWKS = 'https://example.org/jwks';
    private const ISSUER = 'https://example.org';
    private const AUDIENCE = 'a-client-id';

    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();
    }

    // ── The verifier ──────────────────────────────────────────────────

    public function testSomethingWithoutThreePartsIsNotAToken(): void
    {
        self::assertNull($this->verify('not-a-token'));
        self::assertNull($this->verify('two.parts'));
    }

    public function testAHeaderThatIsNotJsonIsRefused(): void
    {
        // Refused on shape before anything is fetched, so a malformed
        // token costs no round trip to the provider.
        self::assertNull($this->verify($this->token('~~~', '~~~', 'sig')));
        self::assertSame(0, FakeWpHttp::callCount());
    }

    public function testATokenSigningItselfWithNoAlgorithmIsRefused(): void
    {
        // "alg": "none" is the oldest trick there is, and HMAC is the
        // second oldest — a verifier that accepted HS256 would verify
        // tokens against the provider's own public key as the secret.
        foreach (['none', 'HS256'] as $alg) {
            self::assertNull($this->verify($this->signedShape(['alg' => $alg, 'kid' => 'k1'])), $alg . ' was accepted.');
        }
    }

    public function testATokenNamingNoKeyIsRefused(): void
    {
        // Without a kid there is nothing to look up, and picking a key
        // by guessing would defeat rotation.
        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256'])));
        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256', 'kid' => ''])));
    }

    public function testAKeySetThatCannotBeFetchedRefusesRatherThanThrows(): void
    {
        FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));
        FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));

        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256', 'kid' => 'k1'])));
    }

    public function testAKeySetThatIsNotAKeySetIsRefused(): void
    {
        FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');
        FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');

        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256', 'kid' => 'k1'])));
    }

    public function testAKeyThatIsNotAnRsaKeyIsRefused(): void
    {
        // The DER is hand-rolled for RSA only; handing it an EC key
        // would build a PEM that nothing can verify against.
        $jwks = (string) wp_json_encode(['keys' => [['kid' => 'k1', 'kty' => 'EC', 'n' => 'aaa', 'e' => 'AQAB']]]);

        FakeWpHttp::pushResponse(200, $jwks);
        FakeWpHttp::pushResponse(200, $jwks);

        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256', 'kid' => 'k1'])));
    }

    public function testAnRsaKeyMissingItsModulusIsRefused(): void
    {
        $jwks = (string) wp_json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA', 'n' => '', 'e' => '']]]);

        FakeWpHttp::pushResponse(200, $jwks);
        FakeWpHttp::pushResponse(200, $jwks);

        self::assertNull($this->verify($this->signedShape(['alg' => 'RS256', 'kid' => 'k1'])));
    }

    // ── Facebook ──────────────────────────────────────────────────────

    public function testFacebookNamesItselfAndDemandsPkce(): void
    {
        // The registry keys on the name, and the state store only keeps
        // a verifier for a provider that says it needs one.
        $provider = $this->facebook();

        self::assertSame('facebook', $provider->name());
        self::assertTrue($provider->requiresPkce());
    }

    public function testACallbackWithNoVerifierIsRefusedRatherThanThrown(): void
    {
        // By here the state is consumed and a browser is waiting, so
        // this has to become a redirect with an error rather than a 500.
        self::assertNull($this->facebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', null));
        self::assertNull($this->facebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', ''));
    }

    public function testACodeExchangeThatFailsIsRefused(): void
    {
        FakeWpHttp::push(new WP_Error('http_request_failed', 'offline'));

        self::assertNull($this->facebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'));
    }

    public function testAnExchangeThatAnswersNoIdTokenIsRefused(): void
    {
        FakeWpHttp::pushResponse(200, '{"access_token":"an-access-token"}');

        self::assertNull($this->facebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'));
    }

    public function testAnExchangeRefusedByFacebookIsRefusedHere(): void
    {
        FakeWpHttp::pushResponse(400, '{"error":{"message":"bad code"}}');

        self::assertNull($this->facebook()->handleCallback('a-code', 'a-nonce', 'https://example.org/cb', 'verifier'));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function facebook(): FacebookProvider
    {
        $settings = new Settings();
        $settings->setClientId('facebook', self::AUDIENCE);
        $settings->setClientSecret('facebook', 'a-client-secret');

        return new FacebookProvider($settings, new JwtVerifier());
    }

    /** @return array<string, mixed>|null */
    private function verify(string $jwt): ?array
    {
        return (new JwtVerifier())->verify($jwt, self::JWKS, self::ISSUER, self::AUDIENCE);
    }

    /** @param array<string, mixed> $header */
    private function signedShape(array $header): string
    {
        return $this->token(
            (string) wp_json_encode($header),
            (string) wp_json_encode(['iss' => self::ISSUER, 'aud' => self::AUDIENCE, 'email' => 'dave@example.org']),
            'a-signature',
        );
    }

    private function token(string $header, string $payload, string $signature): string
    {
        return implode('.', array_map(
            static fn(string $part): string => rtrim(strtr(base64_encode($part), '+/', '-_'), '='),
            [$header, $payload, $signature],
        ));
    }
}
