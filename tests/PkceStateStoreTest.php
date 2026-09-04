<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Auth\StateStore;
use Fellowship\Core\Settings;
use PHPUnit\Framework\TestCase;

/**
 * PKCE, and the one property that makes it worth having.
 *
 * <b>The verifier must never leave this server.</b> Only its SHA-256
 * challenge goes out on the authorise leg; the verifier itself is held
 * in the state transient and produced again at the token exchange. Leak
 * it — into the start response, into the authorization URL — and PKCE
 * protects nothing at all, while still appearing to work end to end.
 * Nothing about a working sign-in would reveal the mistake, which is
 * exactly why it is asserted here.
 */
final class PkceStateStoreTest extends TestCase
{
    private const REDIRECT = 'https://aa-bristol.org/wp-json/fellowship/v1/auth/callback';

    protected function setUp(): void
    {
        parent::setUp();

        WpState::reset();
        WpState::$options[Settings::OPTION_PUBLIC] = [
            'client_id_facebook'  => 'fb-app-id',
            'client_id_microsoft' => 'ms-client-id',
            'client_id_google'    => 'google-client-id',
        ];
    }

    public function testAVerifierSurvivesTheRoundTrip(): void
    {
        $store = new StateStore();

        $issued = $store->issue('facebook', 'link://auth', 'the-verifier');
        $consumed = $store->consume($issued['state']);

        self::assertNotNull($consumed);
        self::assertSame('the-verifier', $consumed['code_verifier']);
        self::assertSame('facebook', $consumed['provider']);
    }

    public function testAFlowWithNoVerifierAnswersNullRatherThanEmptyString(): void
    {
        // Google and Apple pass nothing. The distinction matters because
        // FacebookProvider treats an empty string as "no verifier" and
        // refuses; a store that turned null into '' would make every
        // Facebook exchange fail with no explanation.
        $store = new StateStore();

        $issued = $store->issue('google', 'link://auth');
        $consumed = $store->consume($issued['state']);

        self::assertNotNull($consumed);
        self::assertNull($consumed['code_verifier']);
    }

    public function testTheStateIsSingleUse(): void
    {
        $store = new StateStore();

        $issued = $store->issue('facebook', 'link://auth', 'the-verifier');

        self::assertNotNull($store->consume($issued['state']));
        self::assertNull($store->consume($issued['state']), 'A replayed callback must find nothing.');
    }

    public function testTheAuthorizationUrlCarriesTheChallengeAndNotTheVerifier(): void
    {
        $verifier = 'a-verifier-nobody-outside-this-server-should-see';
        $url = $this->facebook()->getAuthorizationUrl('state-1', 'nonce-1', self::REDIRECT, $verifier);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        self::assertSame('S256', $query['code_challenge_method'] ?? null);
        self::assertSame(
            rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            $query['code_challenge'] ?? null,
        );

        self::assertStringNotContainsString(
            $verifier,
            $url,
            'The verifier must never appear in a URL that goes through a browser.',
        );
    }

    public function testFacebookRefusesToBuildAUrlWithNoVerifier(): void
    {
        // Loud rather than silent: a URL built without a challenge would
        // produce a token exchange that fails much later, with an error
        // naming neither this call nor the omission.
        $this->expectException(\LogicException::class);

        $this->facebook()->getAuthorizationUrl('state-1', 'nonce-1', self::REDIRECT);
    }

    public function testFacebookRefusesACallbackWithNoVerifier(): void
    {
        // Null here rather than the exception above: by the callback a
        // browser is waiting and the state is already spent, so this has
        // to become a redirect carrying an error rather than a 500.
        self::assertNull($this->facebook()->handleCallback('a-code', 'nonce-1', self::REDIRECT));
    }

    public function testOnlyFacebookAsksForPkce(): void
    {
        // The controller mints a verifier from this answer alone, so a
        // provider that lied would either lose PKCE or put an unused
        // secret in a transient.
        self::assertTrue($this->facebook()->requiresPkce());
        self::assertFalse($this->microsoft()->requiresPkce());
        self::assertFalse($this->google()->requiresPkce());
    }

    public function testMicrosoftPinsTheConsumerTenant(): void
    {
        // The `common` endpoint would let any tenant admin mint a token
        // asserting any address, which is an impersonation route straight
        // past the member gate. The consumers tenant is what makes the
        // email in the token trustworthy, so it is asserted rather than
        // left to a comment.
        $url = $this->microsoft()->getAuthorizationUrl('state-1', 'nonce-1', self::REDIRECT);

        self::assertStringStartsWith('https://login.microsoftonline.com/consumers/', $url);
        self::assertStringNotContainsString('/common/', $url);
    }

    public function testTheProvidersAskForNoMoreThanTheyNeed(): void
    {
        // The point of every one of these flows is a verified address.
        // A wider scope is a worse consent screen and a larger token to
        // lose, for something no part of this plugin reads.
        parse_str((string) parse_url($this->google()->getAuthorizationUrl('s', 'n', self::REDIRECT), PHP_URL_QUERY), $g);
        parse_str((string) parse_url($this->facebook()->getAuthorizationUrl('s', 'n', self::REDIRECT, 'v'), PHP_URL_QUERY), $f);

        self::assertSame('openid email', $g['scope'] ?? null);
        self::assertSame('openid email', $f['scope'] ?? null);

        // Microsoft is the exception, and needs saying: without `profile`
        // it will not populate preferred_username, which is the fallback
        // the address is read from when `email` is absent.
        parse_str((string) parse_url($this->microsoft()->getAuthorizationUrl('s', 'n', self::REDIRECT), PHP_URL_QUERY), $m);
        self::assertSame('openid email profile', $m['scope'] ?? null);
    }

    public function testTheServerSideProvidersRefuseAClientSuppliedToken(): void
    {
        // Reaching this would mean the registry dispatched a server-side
        // provider down the client-side path: a wiring fault, and loud.
        foreach ([$this->google(), $this->microsoft(), $this->facebook()] as $provider) {
            try {
                $provider->verifyIdToken('a.b.c', 'nonce');
                self::fail($provider->name() . ' accepted an ID token it cannot verify.');
            } catch (\LogicException) {
                self::assertTrue(true);
            }
        }
    }

    private function facebook(): FacebookProvider
    {
        return new FacebookProvider(new Settings(), new \Fellowship\Auth\JwtVerifier());
    }

    private function microsoft(): MicrosoftProvider
    {
        return new MicrosoftProvider(new Settings(), new \Fellowship\Auth\JwtVerifier());
    }

    private function google(): GoogleProvider
    {
        return new GoogleProvider(new Settings(), new \Fellowship\Auth\JwtVerifier());
    }
}
