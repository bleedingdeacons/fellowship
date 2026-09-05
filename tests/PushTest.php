<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\Device;
use Fellowship\Messaging\Message;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Push\ServiceAccount;

/**
 * Pushing a message to a handset.
 *
 * <b>Push is the fast path, never the reliable one</b>, and almost
 * everything here is about holding that line. Every failure below has to
 * end in false rather than an exception, because the message is already
 * stored and the handset will collect it on its next poll — a throw here
 * would turn a late message into a failed send for everybody else on the
 * same fan-out.
 *
 * The one distinction the client makes is worth keeping: a 401 or 403 is
 * a *configuration* fault that stops every push to everyone until
 * somebody fixes it, and is logged as an error. Anything else is about
 * one message — a dead registration token, a rate limit, a bad hour at
 * Google — and is a warning. Collapsing the two would either bury the
 * outage or cry wolf about a stale token.
 *
 * @covers \Fellowship\Push\FcmClient
 * @covers \Fellowship\Push\FcmTransport
 * @covers \Fellowship\Push\ServiceAccount
 */
final class PushTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();
    }

    // ── The service account ───────────────────────────────────────────

    public function testAServiceAccountIsReadFromItsJson(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());

        self::assertNotNull($account);
        self::assertSame('intergroup-fellowship', $account->projectId);
        self::assertStringContainsString('intergroup-fellowship', $account->sendEndpoint());
    }

    public function testJsonThatIsNotAServiceAccountIsRefused(): void
    {
        // Parsed when it is saved rather than at the first message: a
        // setting that looks stored and pushes nothing is the worst of
        // both.
        self::assertNull(ServiceAccount::fromJson(''));
        self::assertNull(ServiceAccount::fromJson('not json'));
        self::assertNull(ServiceAccount::fromJson('{"project_id":"x"}'));
    }

    public function testTheFingerprintChangesWithTheAccount(): void
    {
        // It keys the cached access token, so replacing the service
        // account has to invalidate the cache rather than leave a token
        // for the old project in play.
        $first = ServiceAccount::fromJson($this->accountJson());
        $second = ServiceAccount::fromJson($this->accountJson('other-project'));

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertNotSame($first->fingerprint(), $second->fingerprint());
    }

    public function testTheFingerprintIsNotTheAccount(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());

        self::assertNotNull($account);
        self::assertStringNotContainsString('@', $account->fingerprint());
        self::assertStringNotContainsString('intergroup-fellowship', $account->fingerprint());
    }

    // ── The transport ─────────────────────────────────────────────────

    public function testASiteWithNoServiceAccountIsNotConfiguredToPush(): void
    {
        // Checked once by the dispatcher rather than per device, so a
        // site with no account logs one line instead of one per handset.
        self::assertFalse($this->transport()->isConfigured());
    }

    public function testASiteWithAServiceAccountIsConfigured(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        self::assertTrue($this->transport($settings)->isConfigured());
    }

    public function testNothingIsSentWhenThereIsNoServiceAccount(): void
    {
        // False, not an exception: the message is stored and the poll
        // will fetch it.
        self::assertFalse($this->transport()->send($this->device(), $this->message()));
        self::assertSame(0, FakeWpHttp::callCount());
    }

    public function testAHandsetWithNoPushTokenIsNotSentTo(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $device = $this->device(pushToken: '');

        self::assertFalse($this->transport($settings)->send($device, $this->message()));
    }

    public function testAHandsetWithNoPublicKeyIsNotSentTo(): void
    {
        // There would be nothing to seal the payload to, and an unsealed
        // push is the one thing this design refuses: the body would
        // travel through Google in the clear.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $device = $this->device(publicKey: '');

        self::assertFalse($this->transport($settings)->send($device, $this->message()));
    }

    // ── The client ────────────────────────────────────────────────────

    public function testAnUnreachableTokenEndpointMeansNoSend(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testATokenEndpointThatAnswersNoTokenMeansNoSend(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"not_an_access_token":true}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testARefusedSendIsReportedRatherThanThrown(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        // A token, then a 403 from the send endpoint: the configuration
        // fault, which stops every push to everyone.
        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(403, '{"error":{"status":"PERMISSION_DENIED"}}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testADeadRegistrationTokenIsAlsoJustFalse(): void
    {
        // Ordinary and survivable: one handset reinstalled the app.
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(404, '{"error":{"status":"NOT_FOUND"}}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testAMessageFcmAcceptsIsASend(): void
    {
        // The whole path: sign an assertion, exchange it for an access
        // token, post the message. Nothing below this line is reached at
        // all unless the service-account key actually loads.
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{"name":"projects/x/messages/1"}');

        self::assertTrue((new FcmClient())->send($account, ['token' => 'fcm-1']));
        self::assertSame(2, FakeWpHttp::callCount());
    }

    public function testTheMessageGoesToTheProjectsOwnEndpointUnderTheToken(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{}');

        (new FcmClient())->send($account, ['token' => 'fcm-1']);

        $args = FakeWpHttp::sentArgs(1);

        self::assertStringContainsString('intergroup-fellowship', FakeWpHttp::sentUrl(1));
        self::assertSame('Bearer ya29.token', $args['headers']['Authorization']);
    }

    public function testTheAccessTokenIsReusedRatherThanMintedPerMessage(): void
    {
        // A fan-out to a committee is one token and many sends. Minting
        // one per handset would be an RSA signature and a round trip to
        // Google for every member.
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{}');
        FakeWpHttp::pushResponse(200, '{}');

        $client = new FcmClient();
        $client->send($account, ['token' => 'fcm-1']);
        $client->send($account, ['token' => 'fcm-2']);

        self::assertSame(3, FakeWpHttp::callCount(), 'The token was minted twice.');
    }

    public function testASendThatNeverReachesGoogleIsJustFalse(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testAKeyThatWillNotLoadStopsBeforeAnyRequest(): void
    {
        // The failure the fixture used to have by accident, asserted on
        // purpose — and asserted by call count, which is the only thing
        // that tells it apart from a refusal further down.
        $account = ServiceAccount::fromJson((string) wp_json_encode([
            'type' => 'service_account',
            'project_id' => 'intergroup-fellowship',
            'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
            'private_key' => "-----BEGIN PRIVATE KEY-----
not-a-real-key
-----END PRIVATE KEY-----
",
            'token_uri' => 'https://oauth2.googleapis.com/token',
        ]));

        self::assertNotNull($account);
        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
        self::assertSame(0, FakeWpHttp::callCount());
    }

    // ── Transport to client ───────────────────────────────────────────

    public function testAConfiguredSiteSealsTheBodyAndPushesIt(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{}');

        $device = $this->device(publicKey: $this->publicKey());

        self::assertTrue($this->transport($settings)->send($device, $this->message()));
    }

    public function testTheBodyOnTheWireIsSealedRatherThanReadable(): void
    {
        // What the design is for: the message travels through Google, so
        // the one thing that must never be in the payload is the text.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(200, '{}');

        $this->transport($settings)->send($this->device(publicKey: $this->publicKey()), $this->message());

        $body = (string) (FakeWpHttp::sentArgs(1)['body'] ?? '');

        self::assertStringNotContainsString('Now the 14th', $body);
        self::assertStringNotContainsString('Intergroup moved', $body);
    }

    public function testAHandsetWhoseKeyWillNotLoadIsSkippedRatherThanSentToInTheClear(): void
    {
        // A key that is present but unusable is the case worth being
        // sure about: an empty one is refused a step earlier.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        self::assertFalse($this->transport($settings)->send($this->device(publicKey: 'not-a-key'), $this->message()));
        self::assertSame(0, FakeWpHttp::callCount());
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function transport(?Settings $settings = null): FcmTransport
    {
        return new FcmTransport(new FcmClient(), $settings ?? new Settings(), new MessageSealer());
    }

    private function device(string $pushToken = 'fcm-1', string $publicKey = 'spki'): Device
    {
        return new Device(
            4,
            'member@example.org',
            7,
            'Pixel 6a',
            'android',
            $publicKey,
            'fcm',
            $pushToken,
            1788000000,
        );
    }

    private function message(): Message
    {
        return new Message(
            9,
            'uuid-1',
            'dave@example.org',
            7,
            'Dave B',
            'Intergroup moved',
            'Now the 14th.',
            'committee',
            'steering',
            1788000000,
        );
    }

    private function publicKey(): string
    {
        $resource = openssl_pkey_get_private(self::privateKey());
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }

    private function accountJson(string $projectId = 'intergroup-fellowship'): string
    {
        // Structurally real, and signed with a keypair generated for this
        // run. A committed fixture must never carry a usable credential,
        // but a *fake* key is worse than useless here: the assertion is
        // signed before any HTTP call is made, so an unreadable key makes
        // every send return false at the first step and the token
        // exchange, the send and every status branch below it are never
        // reached at all. Tests written against that pass for a reason
        // that has nothing to do with what they claim to assert.
        return (string) wp_json_encode([
            'type' => 'service_account',
            'project_id' => $projectId,
            'client_email' => 'pusher@' . $projectId . '.iam.gserviceaccount.com',
            'private_key' => self::privateKey(),
            'token_uri' => 'https://oauth2.googleapis.com/token',
        ]);
    }

    /** A throwaway RSA key, generated once for the whole run. */
    private static function privateKey(): string
    {
        static $pem = null;

        if ($pem === null) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            if ($resource === false) {
                self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
            }

            openssl_pkey_export($resource, $exported);
            $pem = (string) $exported;
        }

        return $pem;
    }
}
