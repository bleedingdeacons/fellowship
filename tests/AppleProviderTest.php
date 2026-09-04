<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\Providers\AppleProvider;
use Fellowship\Core\Settings;
use PHPUnit\Framework\TestCase;

/**
 * Sign in with Apple, from the token inwards.
 *
 * <b>The provider is thin on purpose and that is exactly why it needs
 * testing.</b> Everything hard lives in {@see JwtVerifier}, so what is
 * left here is a short list of decisions about the claims — and a short
 * list of decisions is where a wrong one hides best. Accepting an
 * unverified address, or forgetting to lower-case one, would produce a
 * member gate that matches the wrong person or nobody at all, in a way
 * that looks like a data problem rather than a code one.
 *
 * A real verifier rather than a stub, because the two are only correct
 * together: substituting a permissive double here would test that the
 * provider reads claims out of an array.
 */
final class AppleProviderTest extends TestCase
{
    private const ISSUER = 'https://appleid.apple.com';
    private const AUDIENCE = 'org.aa-bristol.link';
    private const NONCE = 'the-issued-nonce';
    private const KID = 'apple-key-1';

    /** @var resource|\OpenSSLAsymmetricKey */
    private $key;

    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();
        WpState::reset();

        WpState::$options[Settings::OPTION_PUBLIC] = ['client_id_apple' => self::AUDIENCE];

        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        $this->key = $key;
    }

    public function testAValidTokenYieldsTheVerifiedIdentity(): void
    {
        $identity = $this->verify($this->token());

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
        self::assertSame('apple', $identity->provider);
        self::assertSame('000123.abc.456', $identity->sub);
    }

    public function testTheEmailIsLowerCased(): void
    {
        // Apple will return whatever case the address was registered in.
        // Unity's members are matched on the address, so a capital letter
        // arriving here would be a member who cannot sign in and no
        // explanation on either side.
        $identity = $this->verify($this->token(['email' => 'Member@Example.ORG']));

        self::assertNotNull($identity);
        self::assertSame('member@example.org', $identity->email);
    }

    public function testAnUnverifiedEmailIsRefused(): void
    {
        self::assertNull($this->verify($this->token(['email_verified' => 'false'])));
        self::assertNull($this->verify($this->token(['email_verified' => false])));
    }

    public function testAMissingEmailVerifiedClaimIsRefused(): void
    {
        // Absent is not the same as false, and is treated the same way:
        // the claim is the only evidence the address belongs to whoever
        // is holding the phone.
        self::assertNull($this->verify($this->token(remove: ['email_verified'])));
    }

    public function testABooleanTrueIsAcceptedAsWellAsTheString(): void
    {
        // Apple has shipped this claim as both a JSON boolean and the
        // string "true" depending on the token surface. Accepting only one
        // of them would work until it silently did not.
        $identity = $this->verify($this->token(['email_verified' => true]));

        self::assertNotNull($identity);
    }

    public function testATokenWithNoEmailIsRefused(): void
    {
        self::assertNull($this->verify($this->token(remove: ['email'])));
        self::assertNull($this->verify($this->token(['email' => ''])));
    }

    public function testAPrivateRelayAddressIsAcceptedHere(): void
    {
        // Deliberately not special-cased. A forwarding address is a real,
        // verified Apple address; it simply will not match a Unity member,
        // and refusing it here would move that refusal somewhere with less
        // context to explain it. The member gate is where it stops.
        $identity = $this->verify($this->token(['email' => 'xyz@privaterelay.appleid.com']));

        self::assertNotNull($identity);
        self::assertSame('xyz@privaterelay.appleid.com', $identity->email);
    }

    public function testATokenForAnotherAudienceIsRefused(): void
    {
        // The provider passes the configured client id down as the
        // expected audience; this proves it passes the right one.
        self::assertNull($this->verify($this->token(['aud' => 'com.example.someone-else'])));
    }

    public function testAServerSideCallIsRefusedOutright(): void
    {
        $provider = $this->provider();

        self::assertFalse($provider->isServerSide());

        $this->expectException(\LogicException::class);
        $provider->getAuthorizationUrl('state', 'nonce', 'https://example.org/callback');
    }

    public function testHandlingACallbackIsRefusedOutright(): void
    {
        // Apple has no browser leg. Reaching this would mean the registry
        // dispatched a client-side provider down the server-side path,
        // which is a wiring fault and should be loud.
        $this->expectException(\LogicException::class);

        $this->provider()->handleCallback('code', 'nonce', 'https://example.org/callback');
    }

    private function provider(): AppleProvider
    {
        return new AppleProvider(new Settings(), new JwtVerifier());
    }

    private function verify(string $jwt): ?\Fellowship\Auth\VerifiedIdentity
    {
        FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [$this->jwk()]]));

        return $this->provider()->verifyIdToken($jwt, self::NONCE);
    }

    /**
     * @param array<string, mixed> $overrides
     * @param list<string>         $remove
     */
    private function token(array $overrides = [], array $remove = []): string
    {
        $claims = array_merge([
            'iss'            => self::ISSUER,
            'aud'            => self::AUDIENCE,
            'sub'            => '000123.abc.456',
            'email'          => 'member@example.org',
            'email_verified' => 'true',
            'nonce'          => self::NONCE,
            'iat'            => time(),
            'exp'            => time() + 600,
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

    /**
     * @return array<string, string>
     */
    private function jwk(): array
    {
        $details = openssl_pkey_get_details($this->key);
        self::assertIsArray($details);

        return [
            'kty' => 'RSA',
            'kid' => self::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => $this->base64Url($details['rsa']['n']),
            'e'   => $this->base64Url($details['rsa']['e']),
        ];
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
