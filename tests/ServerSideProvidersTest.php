<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Auth\Providers\OAuthProvider;
use Fellowship\Core\Settings;

/**
 * The three browser-leg providers, from the callback inwards.
 *
 * <b>Each one exchanges a code and then decides whether to believe the
 * address in the token that comes back.</b> They differ in exactly one
 * respect that matters, and it is the respect a copy-paste between them
 * would destroy:
 *
 *  - <b>Google and Facebook require `email_verified`</b>, and reject an
 *    absent claim as firmly as a false one. OIDC mandates it; a token
 *    without it is non-compliant or doctored, and either way the address
 *    is not one to match a member against.
 *  - <b>Microsoft has no such claim on a consumer token</b>, so requiring
 *    it would refuse every sign-in. What stands in its place is the
 *    pinned issuer: on the MSA consumer tenant the address is one
 *    Microsoft verified, which is not true on the common endpoint where
 *    any tenant admin can mint a token asserting anything.
 *
 * Every test here mints a real RS256 token and serves a real JWKS, so
 * what is exercised is the provider's decision rather than a stubbed
 * answer about it.
 *
 * @covers \Fellowship\Auth\Providers\GoogleProvider
 * @covers \Fellowship\Auth\Providers\MicrosoftProvider
 * @covers \Fellowship\Auth\Providers\FacebookProvider
 */
final class ServerSideProvidersTest extends TestCase
{
    private const REDIRECT = 'https://aa-bristol.org/wp-json/fellowship/v1/auth/callback';
    private const NONCE = 'the-issued-nonce';
    private const KID = 'test-key-1';

    /** @var resource|\OpenSSLAsymmetricKey */
    private $key;

    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();

        WpState::$options[Settings::OPTION_PUBLIC] = [
            'client_id_google' => 'google-client-id',
            'client_id_microsoft' => 'ms-client-id',
            'client_id_facebook' => 'fb-app-id',
        ];

        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $this->key = $key;
    }

    // ── Google ────────────────────────────────────────────────────────

    public function testGoogleAcceptsAVerifiedAddress(): void
    {
        $identity = $this->exchange($this->google(), [
            'iss' => 'https://accounts.google.com',
            'aud' => 'google-client-id',
            'email_verified' => true,
        ]);

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
        self::assertSame('google', $identity->provider);
    }

    public function testGoogleRefusesAnUnverifiedAddress(): void
    {
        self::assertNull($this->exchange($this->google(), [
            'iss' => 'https://accounts.google.com',
            'aud' => 'google-client-id',
            'email_verified' => false,
        ]));
    }

    public function testGoogleRefusesATokenWithNoVerifiedClaimAtAll(): void
    {
        // Absent is rejected as firmly as false: OIDC requires it, so a
        // token without one is non-compliant or doctored.
        self::assertNull($this->exchange($this->google(), [
            'iss' => 'https://accounts.google.com',
            'aud' => 'google-client-id',
        ], remove: ['email_verified']));
    }

    public function testGoogleLowersTheAddress(): void
    {
        $identity = $this->exchange($this->google(), [
            'iss' => 'https://accounts.google.com',
            'aud' => 'google-client-id',
            'email' => 'Member@Example.ORG',
            'email_verified' => true,
        ]);

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
    }

    public function testGoogleAsksForNothingBeyondAnAddress(): void
    {
        $url = $this->google()->getAuthorizationUrl('state-1', self::NONCE, self::REDIRECT);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        self::assertSame('openid email', $query['scope'] ?? null);
        // A phone is often shared or carries several accounts, and
        // silently reusing whichever Google saw last would enrol the
        // wrong member.
        self::assertSame('select_account', $query['prompt'] ?? null);
    }

    // ── Microsoft ─────────────────────────────────────────────────────

    public function testMicrosoftAcceptsAConsumerToken(): void
    {
        $identity = $this->exchange($this->microsoft(), [
            'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
            'aud' => 'ms-client-id',
        ], remove: ['email_verified']);

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
    }

    public function testMicrosoftRefusesATokenFromAnotherTenant(): void
    {
        // The security property the pinned issuer exists for: on the
        // common endpoint any tenant admin can mint a token asserting any
        // address, which would be an impersonation route past the gate.
        self::assertNull($this->exchange($this->microsoft(), [
            'iss' => 'https://login.microsoftonline.com/some-other-tenant-guid/v2.0',
            'aud' => 'ms-client-id',
        ], remove: ['email_verified']));
    }

    public function testMicrosoftFallsBackToPreferredUsername(): void
    {
        // Consumer tokens often carry the address there rather than in
        // `email`.
        $identity = $this->exchange($this->microsoft(), [
            'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
            'aud' => 'ms-client-id',
            'preferred_username' => 'member@example.org',
        ], remove: ['email', 'email_verified']);

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
    }

    public function testMicrosoftRefusesAPreferredUsernameThatIsNotAnAddress(): void
    {
        // preferred_username is a display handle by specification, and
        // handing the member gate something that is not an address would
        // match nobody in a way nothing explains.
        self::assertNull($this->exchange($this->microsoft(), [
            'iss' => 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
            'aud' => 'ms-client-id',
            'preferred_username' => 'DaveP',
        ], remove: ['email', 'email_verified']));
    }

    // ── Facebook ──────────────────────────────────────────────────────

    public function testFacebookAcceptsAVerifiedAddress(): void
    {
        $identity = $this->exchange($this->facebook(), [
            'iss' => 'https://www.facebook.com',
            'aud' => 'fb-app-id',
            'email_verified' => true,
        ], verifier: 'the-code-verifier');

        self::assertNotNull($identity);
        self::assertSame('facebook', $identity->provider);
    }

    public function testFacebookRefusesAnUnverifiedAddress(): void
    {
        self::assertNull($this->exchange($this->facebook(), [
            'iss' => 'https://www.facebook.com',
            'aud' => 'fb-app-id',
            'email_verified' => false,
        ], verifier: 'the-code-verifier'));
    }

    public function testFacebookSendsTheVerifierOnTheExchange(): void
    {
        // Its token endpoint refuses an exchange whose authorise leg
        // carried a challenge without a matching verifier.
        $this->exchange($this->facebook(), [
            'iss' => 'https://www.facebook.com',
            'aud' => 'fb-app-id',
            'email_verified' => true,
        ], verifier: 'the-code-verifier');

        $sent = FakeWpHttp::sentArgs(0);
        self::assertSame('the-code-verifier', $sent['body']['code_verifier'] ?? null);
    }

    public function testTheClientSecretIsSentInTheBodyAndNeverTheUrl(): void
    {
        // A secret in a request line lands in every proxy log, access log
        // and tracing span between here and the provider.
        $this->exchange($this->google(), [
            'iss' => 'https://accounts.google.com',
            'aud' => 'google-client-id',
            'email_verified' => true,
        ]);

        self::assertStringNotContainsString('client_secret', FakeWpHttp::sentUrl(0));
        self::assertArrayHasKey('client_secret', FakeWpHttp::sentArgs(0)['body']);
    }

    // ── What they all refuse ──────────────────────────────────────────

    public function testATokenEndpointThatAnswersNoIdTokenIsRefused(): void
    {
        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.x"}');

        self::assertNull($this->google()->handleCallback('a-code', self::NONCE, self::REDIRECT));
    }

    public function testARefusedExchangeIsRefused(): void
    {
        FakeWpHttp::pushResponse(400, '{"error":"invalid_grant"}');

        self::assertNull($this->google()->handleCallback('a-code', self::NONCE, self::REDIRECT));
    }

    public function testAnUnreachableTokenEndpointIsRefused(): void
    {
        FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

        self::assertNull($this->google()->handleCallback('a-code', self::NONCE, self::REDIRECT));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    /**
     * Run a provider's callback against a token it should be willing to
     * read, and answer the identity it made of it.
     *
     * @param array<string, mixed> $claims
     * @param list<string>         $remove
     */
    private function exchange(
        OAuthProvider $provider,
        array $claims,
        array $remove = [],
        ?string $verifier = null
    ): ?\Fellowship\Auth\VerifiedIdentity {
        $token = $this->token($claims, $remove);

        // The token exchange, then the JWKS the verifier fetches.
        FakeWpHttp::pushResponse(200, (string) json_encode(['id_token' => $token]));
        FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [$this->jwk()]]));

        return $provider->handleCallback('a-code', self::NONCE, self::REDIRECT, $verifier);
    }

    /**
     * @param array<string, mixed> $overrides
     * @param list<string>         $remove
     */
    private function token(array $overrides, array $remove): string
    {
        $claims = array_merge([
            'sub' => 'sub-1',
            'email' => 'member@example.org',
            'email_verified' => true,
            'nonce' => self::NONCE,
            'iat' => time(),
            'exp' => time() + 600,
        ], $overrides);

        foreach ($remove as $claim) {
            unset($claims[$claim]);
        }

        $header = $this->base64Url((string) json_encode(['alg' => 'RS256', 'kid' => self::KID, 'typ' => 'JWT']));
        $payload = $this->base64Url((string) json_encode($claims));

        $signature = '';
        openssl_sign($header . '.' . $payload, $signature, $this->key, OPENSSL_ALGO_SHA256);

        return $header . '.' . $payload . '.' . $this->base64Url($signature);
    }

    /** @return array<string, string> */
    private function jwk(): array
    {
        $details = openssl_pkey_get_details($this->key);
        self::assertIsArray($details);

        return [
            'kty' => 'RSA',
            'kid' => self::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function google(): GoogleProvider
    {
        return new GoogleProvider(new Settings(), new JwtVerifier());
    }

    private function microsoft(): MicrosoftProvider
    {
        return new MicrosoftProvider(new Settings(), new JwtVerifier());
    }

    private function facebook(): FacebookProvider
    {
        return new FacebookProvider(new Settings(), new JwtVerifier());
    }
}
